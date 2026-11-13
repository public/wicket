#!/usr/bin/env python3
"""E5 driver (#195): runs bf over the datasets and writes logs/*.jsonl, one JSON object per operation.

  python3 -I run.py series   [--stores fs,s3] [--formats today,age,rustic] [--agents rust,node,small] [--sessions 20]
  python3 -I run.py extras   (cross-agent dedup, prune, concurrent writers, kill -9, integrity, safe restore)
  python3 -I run.py restic   (the restic CLI as a reference, on fs)

Everything it makes is under scratch/ (git-ignored) and removed as it goes; the S3 store is versitygw
in Docker (pinned like ci/restore.sh), on host networking, its data under scratch/s3, with its access
log for request counts. Set WICKET_DOCKER (e.g. "sudo -n docker").
"""
import argparse, json, os, shutil, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BF = str(HERE / "target/release/bundle-formats")
RESTIC = str(HERE / "tools/restic")
SCRATCH = HERE / "scratch"
LOGS = HERE / "logs"
DOCKER = os.environ.get("WICKET_DOCKER", "docker").split()
S3_IMAGE = "versity/versitygw@sha256:8319a530d08d537426e2f855bae5280709795dc73a3f0c347973ef915d6343c5"
S3_PORT = 17071
BUCKET = "e5-bench"
VGW = "e5-versitygw"

# Agents: their trees (name -> dataset). "home" is the agent's $HOME (Claude Code state).
AGENTS = {
    "rust": {"workspace": "rust", "state": "home"},
    "node": {"workspace": "node"},
    "small": {"workspace": "small"},
}
SCALE = os.environ.get("E5_SCALE", "1")


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout


def bf(*args, env=None):
    out = subprocess.run([BF, "measure", "--", BF, *args], text=True, capture_output=True, env=env)
    line = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else "{}"
    return json.loads(line)


def du(path):
    """(bytes, files) under path."""
    b = n = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                b += os.lstat(os.path.join(root, f)).st_size
                n += 1
            except FileNotFoundError:
                pass
    return b, n


class S3:
    def __init__(self):
        self.dir = SCRATCH / "s3"
        self.log = self.dir / "access.log"
        self.pos = 0

    def start(self):
        self.stop()
        shutil.rmtree(self.dir, ignore_errors=True)
        (self.dir / "data" / BUCKET).mkdir(parents=True)
        sh(DOCKER + ["run", "-d", "--name", VGW, "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}",
                     "-v", f"{self.dir}:/v", "-e", "ROOT_ACCESS_KEY=e5key", "-e", "ROOT_SECRET_KEY=e5secret-e5secret",
                     S3_IMAGE, "--port", f"127.0.0.1:{S3_PORT}", "--access-log", "/v/access.log", "posix", "/v/data"])
        for _ in range(100):
            try:
                import socket
                socket.create_connection(("127.0.0.1", S3_PORT), 0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("versitygw did not start")

    def stop(self):
        subprocess.run(DOCKER + ["rm", "-f", VGW], capture_output=True)

    def spec(self, prefix):
        return f"s3:http://127.0.0.1:{S3_PORT}|{BUCKET}|{prefix}/"

    def requests(self):
        """Requests since the last call: counts per operation, and bytes sent by the server."""
        ops, up, down = {}, 0, 0
        num = lambda t: int(t) if t.isdigit() else 0
        with open(self.log, errors="replace") as f:
            f.seek(self.pos)
            for line in f:
                p = line.split()
                if len(p) < 14 or not p[7].startswith("s3_"):
                    continue
                op = p[7]
                ops[op] = ops.get(op, 0) + 1
                if op in ("s3_PutObject", "s3_UploadPart"):
                    up += num(p[13])
                elif op == "s3_GetObject":
                    down += max(num(p[12]), num(p[13]))
            self.pos = f.tell()
        puts = sum(v for k, v in ops.items() if k in ("s3_PutObject", "s3_UploadPart", "s3_CreateMultipartUpload", "s3_CompleteMultipartUpload", "s3_CopyObject"))
        gets = sum(v for k, v in ops.items() if k in ("s3_GetObject",))
        heads = ops.get("s3_HeadObject", 0)
        lists = sum(v for k, v in ops.items() if k.startswith("s3_ListObjects"))
        dels = sum(v for k, v in ops.items() if k.startswith("s3_DeleteObject"))
        return {"puts": puts, "gets": gets, "heads": heads, "lists": lists, "deletes": dels, "bytes_up": up, "bytes_down": down, "ops": ops}

    def stored(self, prefix):
        return du(self.dir / "data" / BUCKET / prefix)


def gen_agent(agent, data):
    shutil.rmtree(data, ignore_errors=True)
    for tree, ds in AGENTS[agent].items():
        sh([BF, "gen", ds, str(data / tree), SCALE])


def session(agent, data, n):
    for tree, ds in AGENTS[agent].items():
        sh([BF, "session", ds, str(data / tree), str(n), SCALE])


def trees(agent, data):
    return [f"{t}={data / t}" for t in AGENTS[agent]]


def digests(path, agent):
    return {t: sh([BF, "digest", str(path / t)]).strip() for t in AGENTS[agent]}


def emit(f, rec):
    f.write(json.dumps(rec) + "\n")
    f.flush()
    print(json.dumps({k: rec[k] for k in rec if k in ("kind", "store", "format", "agent", "session", "wall_s", "added_bytes", "puts", "exit", "error")}), flush=True)


def series(args):
    LOGS.mkdir(exist_ok=True)
    s3 = S3()
    measure_at = {0, 1, 5, 20}
    with open(LOGS / "series.jsonl", "a") as f:
        for store in args.stores.split(","):
            if store == "s3":
                s3.start()
            for agent in args.agents.split(","):
                for fmt in args.formats.split(","):
                    sessions = args.sessions if store == "fs" else min(args.sessions, 5)
                    data = SCRATCH / "data" / agent
                    gen_agent(agent, data)
                    repo = SCRATCH / "repo"
                    shutil.rmtree(repo, ignore_errors=True)
                    spec = f"fs:{repo}" if store == "fs" else s3.spec(f"{fmt}-{agent}")
                    stored_before = (0, 0)
                    if store == "s3":
                        s3.requests()
                    for n in range(0, sessions + 1):
                        if n > 0:
                            session(agent, data, n)
                        r = bf("save", fmt, spec, agent, "agent", *trees(agent, data))
                        stored = du(repo) if store == "fs" else s3.stored(f"{fmt}-{agent}")
                        rec = {"kind": "save", "store": store, "format": fmt, "agent": agent, "session": n, **r,
                               "stored_bytes_total": stored[0], "objects_total": stored[1],
                               "added_bytes": stored[0] - stored_before[0], "added_objects": stored[1] - stored_before[1]}
                        if store == "s3":
                            rec.update(s3.requests())
                        stored_before = stored
                        emit(f, rec)
                        if n in measure_at:
                            want = digests(data, agent)
                            dest = SCRATCH / "restore"
                            shutil.rmtree(dest, ignore_errors=True)
                            r = bf("restore", fmt, spec, agent, "agent", str(dest))
                            ok = digests(dest, agent) == want if r.get("exit") == 0 else False
                            rec = {"kind": "restore", "store": store, "format": fmt, "agent": agent, "session": n, **r, "verified": ok}
                            if store == "s3":
                                rec.update(s3.requests())
                            emit(f, rec)
                            if len(AGENTS[agent]) > 1:
                                shutil.rmtree(dest, ignore_errors=True)
                                r = bf("restore", fmt, spec, agent, "agent", str(dest), "state")
                                ok = sh([BF, "digest", str(dest / "state")]).strip() == want["state"] if r.get("exit") == 0 else False
                                rec = {"kind": "restore_one", "store": store, "format": fmt, "agent": agent, "session": n, "tree": "state", **r, "verified": ok}
                                if store == "s3":
                                    rec.update(s3.requests())
                                emit(f, rec)
                            shutil.rmtree(dest, ignore_errors=True)
                    if store == "fs":
                        r = bf("check", fmt, spec, agent, "agent", "read")
                        emit(f, {"kind": "check_read", "store": store, "format": fmt, "agent": agent, "session": sessions, **r})
                        before = du(repo)
                        r = bf("prune", fmt, spec, agent, "agent", "1")
                        after = du(repo)
                        want = digests(data, agent)
                        dest = SCRATCH / "restore"
                        shutil.rmtree(dest, ignore_errors=True)
                        rr = bf("restore", fmt, spec, agent, "agent", str(dest))
                        ok = digests(dest, agent) == want if rr.get("exit") == 0 else False
                        emit(f, {"kind": "prune", "store": store, "format": fmt, "agent": agent, "session": sessions, **r,
                                 "bytes_before": before[0], "bytes_after": after[0], "objects_before": before[1], "objects_after": after[1],
                                 "restore_after_prune_verified": ok})
                        shutil.rmtree(dest, ignore_errors=True)
                    shutil.rmtree(repo, ignore_errors=True)
            if store == "s3":
                s3.stop()
                shutil.rmtree(s3.dir, ignore_errors=True)
    shutil.rmtree(SCRATCH / "data", ignore_errors=True)


def extras(args):
    LOGS.mkdir(exist_ok=True)
    f = open(LOGS / "extras.jsonl", "a")
    data = SCRATCH / "data"
    # 1. Cross-agent dedup: two agents with the same node tree (a fork). rustic per agent, per zone; ours.
    gen_agent("node", data / "node")
    for fmt, key in (("rustic", "agent"), ("rustic", "zone1"), ("today", "agent"), ("age", "agent")):
        repo = SCRATCH / "repo"
        shutil.rmtree(repo, ignore_errors=True)
        spec = f"fs:{repo}"
        r1 = bf("save", fmt, spec, "node", key, *trees("node", data / "node"))
        b1 = du(repo)[0]
        r2 = bf("save", fmt, spec, "node-fork", key, *trees("node", data / "node"))
        b2 = du(repo)[0]
        emit(f, {"kind": "cross_agent", "format": fmt, "repo_key": key, "first_bytes": b1, "second_added_bytes": b2 - b1,
                 "first": r1, "second": r2})
        shutil.rmtree(repo, ignore_errors=True)
    # 2. Concurrent writers: two saves of one agent at once (as two generations), then check and restore.
    for fmt in ("today", "age", "rustic"):
        repo = SCRATCH / "repo"
        shutil.rmtree(repo, ignore_errors=True)
        spec = f"fs:{repo}"
        bf("save", fmt, spec, "node", "agent", *trees("node", data / "node"))
        procs = []
        for gen in ("2", "3"):
            env = dict(os.environ, E5_GENERATION=gen)
            procs.append(subprocess.Popen([BF, "save", fmt, spec, "node", "agent", *trees("node", data / "node")], env=env,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        outs = [p.communicate() for p in procs]
        codes = [p.returncode for p in procs]
        chk = bf("check", fmt, spec, "node", "agent", "read")
        dest = SCRATCH / "restore"
        shutil.rmtree(dest, ignore_errors=True)
        rr = bf("restore", fmt, spec, "node", "agent", str(dest))
        ok = digests(dest, "node") == digests(data / "node", "node") if rr.get("exit") == 0 else False
        emit(f, {"kind": "concurrent", "format": fmt, "exit_codes": codes, "stderr": [o[1][-300:] for o in outs], "check": chk,
                 "restore_verified": ok})
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(repo, ignore_errors=True)
    # 3. kill -9 mid-save: the previous state must still restore, and the next save must work.
    gen_agent("rust", data / "rust")
    for fmt in ("today", "age", "rustic"):
        repo = SCRATCH / "repo"
        shutil.rmtree(repo, ignore_errors=True)
        spec = f"fs:{repo}"
        first = bf("save", fmt, spec, "rust", "agent", *trees("rust", data / "rust"))
        want0 = digests(data / "rust", "rust")
        session("rust", data / "rust", 1)
        # Kill when about 40% of a full save has passed.
        p = subprocess.Popen([BF, "save", fmt, spec, "rust", "agent", *trees("rust", data / "rust")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(max(0.2, first["wall_s"] * 0.4))
        p.kill()
        p.wait()
        killed_rc = p.returncode
        chk = bf("check", fmt, spec, "rust", "agent", "read")
        # Restore the latest complete state: the first (the killed save never committed).
        dest = SCRATCH / "restore"
        shutil.rmtree(dest, ignore_errors=True)
        rr = bf("restore", fmt, spec, "rust", "agent", str(dest))
        got = digests(dest, "rust") if rr.get("exit") == 0 else {}
        prev_ok = got == want0
        shutil.rmtree(dest, ignore_errors=True)
        again = bf("save", fmt, spec, "rust", "agent", *trees("rust", data / "rust"))
        rr2 = bf("restore", fmt, spec, "rust", "agent", str(dest))
        ok2 = digests(dest, "rust") == digests(data / "rust", "rust") if rr2.get("exit") == 0 else False
        leftovers = du(repo)
        emit(f, {"kind": "kill9", "format": fmt, "killed_rc": killed_rc, "check_after_kill": chk, "previous_restores": prev_ok,
                 "restore_after_kill": rr, "next_save": again, "next_restore_verified": ok2, "repo_bytes": leftovers[0]})
        shutil.rmtree(dest, ignore_errors=True)
        # 4. Integrity: flip one byte in the middle of the largest stored object; check and restore must notice.
        biggest = max((p for p in repo.rglob("*") if p.is_file()), key=lambda p: p.stat().st_size)
        b = bytearray(biggest.read_bytes())
        b[len(b) // 2] ^= 0x01
        os.chmod(biggest, 0o600)
        biggest.write_bytes(bytes(b))
        chk = bf("check", fmt, spec, "rust", "agent", "read")
        rr = bf("restore", fmt, spec, "rust", "agent", str(dest))
        emit(f, {"kind": "tamper", "format": fmt, "object_bytes": len(b), "check": chk, "restore": rr})
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(repo, ignore_errors=True)
    # 5. Safe restore: a tree with a symlink out of it, a dangling link, a FIFO; what each format stores
    # and restores.
    t = data / "odd" / "workspace"
    shutil.rmtree(t.parent, ignore_errors=True)
    (t / "d").mkdir(parents=True)
    (t / "d" / "f").write_text("x")
    os.symlink("/etc", t / "out")
    os.symlink("../nowhere", t / "d" / "dangling")
    os.mkfifo(t / "fifo")
    for fmt in ("today", "age", "rustic"):
        repo = SCRATCH / "repo"
        shutil.rmtree(repo, ignore_errors=True)
        spec = f"fs:{repo}"
        s = bf("save", fmt, spec, "odd", "agent", f"workspace={t}")
        dest = SCRATCH / "restore"
        shutil.rmtree(dest, ignore_errors=True)
        r = bf("restore", fmt, spec, "odd", "agent", str(dest))
        got = sorted(str(p.relative_to(dest)) + (" -> " + os.readlink(p) if p.is_symlink() else "") for p in dest.rglob("*")) if dest.exists() else []
        emit(f, {"kind": "odd_tree", "format": fmt, "save": s, "restore": r, "restored": got})
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(repo, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)


def restic_ref(args):
    """The restic CLI on the same series (fs only, sessions 0, 1, 5): a reference for rustic_core."""
    LOGS.mkdir(exist_ok=True)
    f = open(LOGS / "restic.jsonl", "a")
    env = dict(os.environ, RESTIC_PASSWORD="e5-reference", RESTIC_CACHE_DIR=str(SCRATCH / "restic-cache"))
    for agent in ("rust", "node", "small"):
        data = SCRATCH / "data" / agent
        gen_agent(agent, data)
        repo = SCRATCH / "repo"
        shutil.rmtree(repo, ignore_errors=True)
        sh([RESTIC, "init", "--repo", str(repo)], env=env)
        prev = (0, 0)
        for n in range(0, 6):
            if n > 0:
                session(agent, data, n)
            for tree in AGENTS[agent]:
                r = subprocess.run([BF, "measure", "--", RESTIC, "--repo", str(repo), "backup", "--json", "--quiet", "--host", agent,
                                    "--tag", f"tree={tree}", str(data / tree)], text=True, capture_output=True, env=env)
                rec = json.loads(r.stdout.strip().splitlines()[-1])
                st = du(repo)
                emit(f, {"kind": "restic_backup", "agent": agent, "tree": tree, "session": n, **rec, "added_bytes": st[0] - prev[0],
                         "stored_bytes_total": st[0], "objects_total": st[1]})
                prev = st
            if n in (0, 1, 5):
                dest = SCRATCH / "restore"
                shutil.rmtree(dest, ignore_errors=True)
                r = subprocess.run([BF, "measure", "--", RESTIC, "--repo", str(repo), "restore", "latest", "--target", str(dest), "--json",
                                    "--quiet"], text=True, capture_output=True, env=env)
                rec = json.loads(r.stdout.strip().splitlines()[-1])
                emit(f, {"kind": "restic_restore", "agent": agent, "session": n, **rec})
                shutil.rmtree(dest, ignore_errors=True)
        r = subprocess.run([BF, "measure", "--", RESTIC, "--repo", str(repo), "check", "--read-data", "--quiet"], text=True, capture_output=True, env=env)
        emit(f, {"kind": "restic_check_read", "agent": agent, **json.loads(r.stdout.strip().splitlines()[-1])})
        r = subprocess.run([BF, "measure", "--", RESTIC, "--repo", str(repo), "forget", "--keep-last", "1", "--prune", "--quiet"], text=True,
                           capture_output=True, env=env)
        emit(f, {"kind": "restic_forget_prune", "agent": agent, **json.loads(r.stdout.strip().splitlines()[-1]), "bytes_after": du(repo)[0]})
        shutil.rmtree(repo, ignore_errors=True)
        shutil.rmtree(data, ignore_errors=True)
    shutil.rmtree(SCRATCH / "restic-cache", ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["series", "extras", "restic"])
    ap.add_argument("--stores", default="fs,s3")
    ap.add_argument("--formats", default="today,age,rustic")
    ap.add_argument("--agents", default="rust,node,small")
    ap.add_argument("--sessions", type=int, default=20)
    a = ap.parse_args()
    os.environ.setdefault("E5_SCRATCH", str(SCRATCH / "tmp"))
    (SCRATCH / "tmp").mkdir(parents=True, exist_ok=True)
    {"series": series, "extras": extras, "restic": restic_ref}[a.what](a)


if __name__ == "__main__":
    main()
