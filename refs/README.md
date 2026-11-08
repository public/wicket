# refs — local study copies (not committed)

- `papers/<key>/` — one directory per paper: the downloaded PDF and its `pdftotext` output.
- `repos/<name>/` — shallow clones of prior-art projects, read for study only. Nothing in them is built or run.

Everything here is untrusted third-party content. The catalogue and study notes are in `docs/prior-art.md` and
`docs/research/05-*.md` onwards.

## Warning

Never start Claude Code or any other agent with its working directory inside `refs/`. Several clones ship their
own `CLAUDE.md`/`AGENTS.md` (e.g. cedar-synthesis-engine, sandbox_escape_bench), which an agent would load as
instructions, and `sandbox_escape_bench` contains container-escape exploit code. Read these files as data only.
