# Command line

Every `wicket` command and flag, as `wicket <command> --help` prints it. This page is generated
from the code by `ci/gen-cli-reference.sh`, and CI checks that it matches: edit the commands' doc
comments in `crates/wicket-cli/src/main.rs` (and `place.rs`), not this page.

On an installed host most commands go through the daemon, which allows each one for some callers
only: [the daemon](daemon.md#who-may-run-what) lists which commands need `sudo`. Durations are
humantime strings (`90s`, `10m`, `1h`).
