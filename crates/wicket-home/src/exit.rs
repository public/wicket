//! How `wicket` exits (#574): one code per kind of outcome, the same for every command, so a script
//! can tell "no such thing" from "not allowed" from "waiting for a person" without reading the
//! message. docs/reference/cli.md lists them.
//!
//! A command fails with one of these where it knows which it is ([`not_found`], [`refused`],
//! [`needs_approval`], [`usage`]); `wicket`'s main also reads the store's and placement's own
//! errors. Anything else is [`Code::Failed`].

/// `wicket`'s exit codes. 2 is clap's own for a command line it can't parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Code {
    Ok = 0,
    /// Anything that went wrong and isn't one of the others.
    Failed = 1,
    /// The command line is wrong (clap's code, kept for every usage error).
    Usage = 2,
    /// wicket won't do it: the daemon's policy for this caller, the org policy, an operator's no
    /// (at the confirmation, or to a spend), or the state of what it names (a request already
    /// decided, terms wider than the request).
    Refused = 3,
    /// What it names doesn't exist: a request, grant, link, lease, run, agent, node, service.
    NotFound = 4,
    /// It needs an approval nobody has given yet: a spend no capacity grant covers and no operator
    /// decided within --wait, an update no trusted key signed and no operator approved.
    NeedsApproval = 5,
}

/// A failure with its exit code.
#[derive(Debug)]
pub struct Exit {
    pub code: Code,
    pub msg: String,
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Exit {}

impl Exit {
    /// A [`Code::Refused`] to add as context (`e.context(Exit::refused(…))`), over a cause.
    pub fn refused(msg: impl Into<String>) -> Exit {
        Exit { code: Code::Refused, msg: msg.into() }
    }
}

fn exit(code: Code, msg: impl Into<String>) -> anyhow::Error {
    Exit { code, msg: msg.into() }.into()
}

/// [`Code::NotFound`].
pub fn not_found(msg: impl Into<String>) -> anyhow::Error {
    exit(Code::NotFound, msg)
}

/// [`Code::Refused`].
pub fn refused(msg: impl Into<String>) -> anyhow::Error {
    exit(Code::Refused, msg)
}

/// [`Code::NeedsApproval`].
pub fn needs_approval(msg: impl Into<String>) -> anyhow::Error {
    exit(Code::NeedsApproval, msg)
}

/// [`Code::Usage`].
pub fn usage(msg: impl Into<String>) -> anyhow::Error {
    exit(Code::Usage, msg)
}

/// The code an [`Exit`] in `e` says, if one does: the innermost error that says one, else an
/// [`Exit`] added as `e`'s context (a refusal over a cause that says nothing more specific).
pub fn code_of(e: &anyhow::Error) -> Option<Code> {
    let inner = e.chain().filter_map(|c| c.downcast_ref::<Exit>()).last();
    inner.or_else(|| e.downcast_ref::<Exit>()).map(|x| x.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_innermost_code_wins_and_context_counts() {
        assert_eq!(code_of(&anyhow::anyhow!("plain")), None);
        assert_eq!(code_of(&not_found("no grant g-1")), Some(Code::NotFound));
        // Context over a code keeps the code, and the message.
        let e = not_found("no grant g-1").context("renewing");
        assert_eq!(code_of(&e), Some(Code::NotFound));
        assert!(format!("{e:#}").contains("no grant g-1"));
        // A refusal added as context: its own code, unless the cause says one.
        assert_eq!(code_of(&anyhow::anyhow!("outside its authority").context(Exit::refused("refused"))), Some(Code::Refused));
        assert_eq!(code_of(&not_found("no grant g-1").context(Exit::refused("refused"))), Some(Code::NotFound));
    }
}
