//! wicket's restore rules, applied to a restic snapshot's listing before anything is written: only
//! regular files, directories and symlinks; every path made of plain components (no `..`, no
//! absolute paths, no empty or `/`-containing names); no entry under a symlink (a crafted tree could
//! list `a -> /etc` and then `a/passwd`); no name twice in a directory.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
pub struct Listing {
    links: HashSet<PathBuf>,
    seen: HashSet<PathBuf>,
}

impl Listing {
    pub fn check(&mut self, path: &Path, node: &rustic_core::repofile::Node) -> Result<(), String> {
        use rustic_core::repofile::NodeType;
        if path.as_os_str().is_empty() {
            return Ok(()); // the tree's root
        }
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!("{} is not a plain relative path", path.display()));
        }
        let name = node.name();
        let name = name.to_string_lossy();
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(format!("{}: bad name {name:?}", path.display()));
        }
        if !self.seen.insert(path.to_path_buf()) {
            return Err(format!("{} appears twice", path.display()));
        }
        if path.ancestors().skip(1).any(|a| self.links.contains(a)) {
            return Err(format!("{} is under a symlink", path.display()));
        }
        match &node.node_type {
            NodeType::File | NodeType::Dir => Ok(()),
            NodeType::Symlink { .. } => {
                self.links.insert(path.to_path_buf());
                Ok(())
            }
            other => Err(format!("{}: a {other:?} entry", path.display())),
        }
    }
}
