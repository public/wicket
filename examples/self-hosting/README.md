# Example: wicket working on wicket

An example of a project describing its own workload to wicket: an agent that works on wicket's
source, inside a wicket sandbox. Nothing here is part of wicket; any project would write its own
image and manifest the same way.

What the manifest gives the agent:
- **Its own image** (`agent.image: wicket-self:dev`, listed in `zone.images`), with Rust and a C
  compiler, so a run started from the console gets it too. `wicket run --image` still overrides it.
- **The checkout, mounted in place** (`--workspace-dir`), so commits land in a real clone on the host.
- **Two volumes** that persist between runs: cargo's registry cache and the build directory.
- **Reads** of crates.io, this repository over git, and its issues and pull requests on GitHub.
- **Writes that wait for you:** pushes and creating pull requests are outside the reach, so each one
  is a pending request. GitHub's branch protection keeps `main` closed regardless.
- **No credentials in the box.** If you store a token, wicket injects it at the proxy; without one,
  reads are anonymous and writes fail at GitHub after you approve them.

Setup, once:

```sh
# The image (from the repository root).
wicket image --tag wicket-self:dev --dir examples/self-hosting

# A separate clone for the agent to work in, with an HTTPS remote (the box can't use SSH).
git clone https://github.com/public/wicket.git ../wicket-self
git -C ../wicket-self config user.name "…"; git -C ../wicket-self config user.email "…"

# Optional, for pushes and pull requests: a fine-grained GitHub token limited to this repository
# (Contents: read and write; Pull requests: read and write), typed into the terminal, never a chat.
wicket secret set github-wicket --hosts github.com,api.github.com
```

Each session:

```sh
wicket run examples/self-hosting/manifest.yaml \
  --workspace-dir ../wicket-self --task "Fix …, run the tests, and commit on a new branch."
wicket say <run> "Also …"          # follow-ups while it runs; it stays open until it finishes
```
