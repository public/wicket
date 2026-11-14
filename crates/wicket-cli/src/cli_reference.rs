//! docs/reference/cli.md against the commands' own help (#219): every visible command's `--help`,
//! rendered here as the binary prints it, must be its section's code block, and the page must have
//! a section for every visible command and no other. A unit test, so the check costs no build of its
//! own; `ci/gen-cli-reference.sh` still writes the page from the binary.

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use std::collections::BTreeMap;

    /// `wicket <path> --help`, for every visible command, depth-first.
    fn helps() -> BTreeMap<String, String> {
        let mut root = crate::Cli::command();
        root.build();
        let mut out = BTreeMap::new();
        fn walk(c: &mut clap::Command, path: Vec<String>, out: &mut BTreeMap<String, String>) {
            let name = std::iter::once("wicket".to_string()).chain(path.iter().cloned()).collect::<Vec<_>>().join(" ");
            // `--help` prints the long layout only when there is long help to show (clap's rule),
            // else the short one.
            let long = |a: &clap::Arg| {
                !a.is_hide_set()
                    && (a.get_long_help().is_some()
                        || a.is_hide_long_help_set()
                        || a.is_hide_short_help_set()
                        || (!a.is_hide_possible_values_set() && a.get_possible_values().iter().any(|v| v.get_help().is_some())))
            };
            let use_long = c.get_long_about().is_some()
                || c.get_before_long_help().is_some()
                || c.get_after_long_help().is_some()
                || c.get_arguments().any(long);
            let help = if use_long { c.render_long_help() } else { c.render_help() };
            out.insert(name, help.to_string().trim_end().to_string());
            let subs: Vec<String> =
                c.get_subcommands().filter(|s| !s.is_hide_set() && s.get_name() != "help").map(|s| s.get_name().to_string()).collect();
            for s in subs {
                let mut p = path.clone();
                p.push(s.clone());
                let sub = c.find_subcommand_mut(&s).expect("listed");
                walk(sub, p, out);
            }
        }
        walk(&mut root, vec![], &mut out);
        out
    }

    /// The page's sections: "## `wicket x`" headings (any depth) and the text block after each.
    fn sections(page: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut lines = page.lines();
        while let Some(l) = lines.next() {
            let Some(name) = l.trim_start_matches('#').strip_prefix(" `").and_then(|r| r.strip_suffix('`')) else { continue };
            if !l.starts_with("##") {
                continue;
            }
            let mut block = vec![];
            let mut inside = false;
            for b in lines.by_ref() {
                if b == "```text" {
                    inside = true;
                } else if b == "```" && inside {
                    break;
                } else if inside {
                    block.push(b);
                }
            }
            out.insert(name.to_string(), block.join("\n").trim_end().to_string());
        }
        out
    }

    #[test]
    fn the_cli_reference_matches_the_commands_help() {
        let page = include_str!("../../../docs/reference/cli.md");
        let (want, got) = (helps(), sections(page));
        let missing: Vec<_> = want.keys().filter(|k| !got.contains_key(*k)).collect();
        let extra: Vec<_> = got.keys().filter(|k| !want.contains_key(*k)).collect();
        let differ: Vec<_> = want.iter().filter(|(k, v)| got.get(*k).is_some_and(|g| g != *v)).map(|(k, _)| k).collect();
        if let Some(k) = differ.first() {
            eprintln!("--- docs/reference/cli.md, `{k}`\n{}\n--- its --help\n{}", got[*k], want[*k]);
        }
        assert!(
            missing.is_empty() && extra.is_empty() && differ.is_empty(),
            "docs/reference/cli.md is out of date (run WICKET=target/debug/wicket ci/gen-cli-reference.sh): missing {missing:?}, extra {extra:?}, different {differ:?}"
        );
    }
}
