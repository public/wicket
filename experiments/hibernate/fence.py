#!/usr/bin/env python3
"""Double wake and split brain: a lease + fencing sketch, raced for real.

The ledger is SQLite (wicket's single-host ledger). An agent row holds its lifecycle state, a
generation (the fencing token), the current activation and its lease, and the head manifest seq.

- wake():   compare-and-set Hibernated -> Waking, generation += 1, lease to this waker. Exactly one
            of any number of concurrent wakers wins; the rest see "already waking".
- proxy():  every request through the box's sockets carries the activation's generation (wicket binds
            it to the socket, the box never sees it); a stale generation is refused.
- commit(): a push writes blobs and a manifest object keyed by (seq, generation), then one ledger
            transaction checks the generation and moves the head. A stale twin's push can't become the head.

Run: fence.py [N]   (N races of 8 concurrent wakers each; default 500)
"""
import os
import sqlite3
import sys
import tempfile
import threading
import time

DB = os.path.join(tempfile.mkdtemp(prefix="hib-fence-"), "ledger.db")


def conn():
    c = sqlite3.connect(DB, timeout=30, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def setup():
    c = conn()
    c.execute("CREATE TABLE agent (id TEXT PRIMARY KEY, state TEXT, gen INTEGER, activation TEXT, lease_until REAL, head_seq INTEGER)")
    c.execute("CREATE TABLE manifest (agent TEXT, seq INTEGER, gen INTEGER, PRIMARY KEY (agent, seq))")
    c.execute("INSERT INTO agent VALUES ('a1', 'hibernated', 0, NULL, 0, 1)")
    c.execute("INSERT INTO manifest VALUES ('a1', 1, 0)")


def wake(c, activation, lease_s=60.0):
    """Claim: one UPDATE, conditional on the state. Returns the new generation, or None."""
    now = time.time()
    cur = c.execute(
        "UPDATE agent SET state='waking', gen=gen+1, activation=?, lease_until=? "
        "WHERE id='a1' AND (state='hibernated' OR (state IN ('waking','active') AND lease_until < ?))",
        (activation, now + lease_s, now))
    if cur.rowcount != 1:
        return None
    return c.execute("SELECT gen FROM agent WHERE id='a1'").fetchone()[0]


def proxy(c, gen):
    """What the LLM/egress proxy checks per request (cached per connection in practice)."""
    row = c.execute("SELECT gen, state, lease_until FROM agent WHERE id='a1'").fetchone()
    return row[0] == gen and row[1] in ("waking", "active") and row[2] > time.time()


def commit(c, gen, seq):
    """Hibernate push. The blobs and the manifest object are written first, under a key that names the
    generation (m/<seq>.<gen>), so a stale writer can only leave an orphan. Then one ledger transaction
    checks the generation and moves the head: that is the only commit point."""
    c.execute("BEGIN IMMEDIATE")
    try:
        ok = c.execute("SELECT 1 FROM agent WHERE id='a1' AND gen=? AND head_seq=?", (gen, seq - 1)).fetchone()
        if not ok:
            c.execute("ROLLBACK")
            return "refused: stale generation or seq"
        c.execute("INSERT INTO manifest VALUES ('a1', ?, ?)", (seq, gen))
        c.execute("UPDATE agent SET head_seq=?, state='hibernated', activation=NULL WHERE id='a1'", (seq,))
        c.execute("COMMIT")
        return "committed"
    except Exception:
        c.execute("ROLLBACK")
        raise


def race(n_wakers=8):
    barrier = threading.Barrier(n_wakers)
    won = []

    def w(i):
        c = conn()
        barrier.wait()
        g = wake(c, f"act-{i}")
        if g is not None:
            won.append((i, g))

    ts = [threading.Thread(target=w, args=(i,)) for i in range(n_wakers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return won


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    setup()
    c = conn()
    winners = []
    t0 = time.time()
    for _ in range(n):
        won = race()
        winners.append(len(won))
        gen = won[0][1]
        seq = c.execute("SELECT head_seq FROM agent").fetchone()[0] + 1
        assert commit(c, gen, seq) == "committed"
    dt = time.time() - t0
    print(f"races: {n} x 8 concurrent wakers; winners per race: min {min(winners)} max {max(winners)}; "
          f"{dt / n * 1000:.2f} ms per race (claim + commit)")

    # Split brain, step by step: a twin restored from an old image (or a waker whose lease expired).
    g1 = wake(c, "act-A")
    print(f"wake A: gen {g1}; proxy accepts A: {proxy(c, g1)}")
    print(f"wake B while A holds the lease: {wake(c, 'act-B')}")
    c.execute("UPDATE agent SET lease_until=? WHERE id='a1'", (time.time() - 1,))  # A's node went silent
    g2 = wake(c, "act-B")
    print(f"A's lease expired; wake B: gen {g2}; proxy accepts B: {proxy(c, g2)}; proxy accepts stale A: {proxy(c, g1)}")
    head = c.execute("SELECT head_seq FROM agent").fetchone()[0]
    print(f"stale A pushes seq {head + 1}: {commit(c, g1, head + 1)}")
    print(f"B pushes seq {head + 1}: {commit(c, g2, head + 1)}")
    print(f"B is hibernated again; stale A tries once more: {commit(c, g1, head + 2)}; proxy accepts A: {proxy(c, g1)}")
    print("=> the head only moves under the current generation; A's manifest object is an orphan for GC.")


if __name__ == "__main__":
    main()
