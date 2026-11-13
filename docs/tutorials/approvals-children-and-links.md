# Approvals, children and links

In this tutorial an agent starts boxes of its own. You will watch it start a child in a narrower
zone, which needs nobody; try one in a wider zone, which it can't; approve that one yourself; and
see it link to a service it started and fetch a page across the link.

You need the setup from [your first box](first-box.md): wicket built and on your `PATH`, the image,
the identity issuer and `claude-oauth` linked. Work in the `wicket` checkout. The agent's own
words will differ from run to run; wicket's lines, shown here, won't, except for ids and times.

## 1. Write the lead agent's manifest

Save this as `lead.yaml`:

```yaml
task: |
  You lead a small team, using wicket's MCP tools. Do these in order and report each result in
  /workspace/out/result.json:
  1. spawn an agent named "reader" whose zone reaches only example.com, with the task "Fetch
     https://example.com/ and send its title to your parent with send_message". Wait for its
     messages with await_message.
  2. spawn a program named "hn" with command ["curl", "-sS", "https://news.ycombinator.com/"] in
     a zone that reaches news.ycombinator.com. If it is refused, call spawn again with the same
     arguments and ask_human true, wait with await_grant, then call spawn once more.
  3. spawn a program named "web" with command ["python3", "-m", "http.server", "8000"] and an
     empty zone, then connect to it on port 8000 and fetch http://<the address connect gives>/
     with curl. Then unlink the link.
agent:
  name: lead
  max_turns: 40
  max_children: 3
zone:
  name: team
  reach:
    - { host: example.com }
  llm: { max_requests: 80, max_output_tokens: 80000 }
  limits: { memory: 3g, cpus: 2, timeout: 20m }
```

The lead may start three boxes (`max_children: 3`). Its zone reaches example.com only.

## 2. Run it

```sh
wicket run lead.yaml
```

```text
wicket run run_…  tenant t0  zone team  agent lead (claude-code)
  isolation Gvisor, no network; egress and model calls via wicket only
  identity spiffe://wicket.example.com/t/t0/z/team/a/lead  (valid 600s, re-issued every 300s)
  acting for you (cli, unix-user) → lead
  …
```

## 3. A narrower child starts at once

The reader's zone, example.com only, is within the lead's, so `spawn` needs no one:

```text
[wicket-tool] spawn: started agent reader (run_…) …
```

The reader runs in its own box, with its own identity,
`spiffe://wicket.example.com/t/t0/z/team.reader.run_…/a/reader`, acting for you → lead → reader. It
fetches the page, sends the title to the lead, and ends with a signed `run_finished` message:

```text
[wicket-tool] await_message: …
```

## 4. A wider child is refused, then put to you

`hn` wants news.ycombinator.com, which the lead can't reach itself. `spawn` refuses, listing what
exceeds the lead's zone:

```text
[wicket-tool] spawn: … not within your zone: …news.ycombinator.com…
```

The lead calls `spawn` again with `ask_human`, which files exactly that zone as a request. In
another terminal:

```sh
wicket pending
```

```text
r-…  SPAWN wicket.internal/zones/team.hn.run_…/…  [R4ExecOrPrivilege]  run run_…  …s ago
    why: …
    agent: spiffe://wicket.example.com/t/t0/z/team/a/lead [verified]  acting for: you (cli, unix-user) → lead
```

A box beyond its parent's authority is always R4: it is never a one-click allow. Approve it:

```sh
wicket approve r-…
```

wicket prints the request again and asks `approve r-… as shown above? [y/N]`. Answer `y`:

```text
approved r-… → grant g-…: SPAWN wicket.internal/zones/team.hn.run_…/… (1 use(s), 10m, run run_… only)
```

The lead's `await_grant` returns `granted`, it calls `spawn` with the same arguments, and `hn`
starts. Its fetch is allowed by its own zone:

```text
[wicket-tool] spawn: started program hn (run_…) …
```

You could have approved it in the console instead, exactly as in the first tutorial.

## 5. A link to a service

`web` is a program in an empty zone: it can reach nothing, but it serves port 8000. The lead
connects to it. A box's own children can be connected to without `expose` or approval:

```text
[wicket-tool] spawn: started program web (run_…) …
[wicket-tool] connect: web.wicket.internal:8000 …(child)…
```

In the lead's box, `web.wicket.internal` resolves to a link address (198.18.1.x), and wicket relays
each connection into the `web` box. Boxes still have no network. In another terminal:

```sh
wicket links
```

```text
l-…  open    run_… → web.wicket.internal:8000 (run_…)  opened by run_… (child)
```

When the lead unlinks it:

```text
l-…  closed  run_… → web.wicket.internal:8000 (run_…)  opened by run_… (child); closed: unlinked by an agent
```

You can cut any link yourself with `wicket unlink l-…`.

## 6. Who was who

When the run ends, list every identity issued:

```sh
wicket identity list
```

```text
run_…  succeeded  spiffe://wicket.example.com/t/t0/z/team/a/lead [verified]  acting for: you (cli, unix-user) → lead
run_…  succeeded  spiffe://wicket.example.com/t/t0/z/team.reader.run_…/a/reader [verified]  acting for: you (cli, unix-user) → lead → reader
run_…  succeeded  spiffe://wicket.example.com/t/t0/z/team.hn.run_…/a/hn [verified]  acting for: you (cli, unix-user) → lead → hn
…
```

And check that the record holds:

```sh
wicket audit --verify
```

The audit log has `spawn.beyond_parent` for `hn`, and `link.open` and `link.close` for the link.

You have seen an agent build its own team inside its authority, a human widen it exactly once, and
two boxes talk with neither having a network.

Next: [write a zone for a project](../how-to/write-a-zone-for-a-project.md), or read about
[zones and the subset rule](../explanation/concepts.md#zones-and-the-subset-rule) and
[links](../explanation/concepts.md#links).
