//! Who may send whom a message (#250, #252): one rule, decided where the message is sent, by the
//! control host (`RunCtx::send`) and, while the box's node is cut off from it, by the node
//! (`nodegw::send_local`), each from what it knows (#257). The receiver's org layer is checked
//! apart (`OrgLayer::allows_message_from`, wicket-authz): at delivery on the control host, at send
//! on a node cut off.

/// What the sender's side knows of a message's two ends.
pub struct Facts<'a, S: AsRef<str>> {
    /// The receiver is the sender's child.
    pub to_child: bool,
    /// The receiver is the sender's parent.
    pub to_parent: bool,
    /// The receiver's `accept_from`.
    pub accept_from: &'a [S],
    pub sender_zone: &'a str,
    /// The sender's principal, when its side knows it.
    pub sender: Option<&'a str>,
    /// It answers (`in_reply_to`) a message the receiver sent the sender.
    pub reply: bool,
}

/// Why a message may go: what it is to its receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// To the sender's child.
    Child,
    /// To the sender's parent.
    Parent,
    /// To a peer whose `accept_from` names the sender or its zone.
    Peer,
    /// An answer to a message the receiver sent, whatever its `accept_from`.
    Reply,
}

impl Relation {
    pub fn as_str(self) -> &'static str {
        match self {
            Relation::Child => "child",
            Relation::Parent => "parent",
            Relation::Peer => "peer",
            Relation::Reply => "reply",
        }
    }
}

/// Whether the message may go, and as what: family first, then the receiver's `accept_from`, then
/// a reply. None: refused ([`refusal`] says why).
pub fn relation<S: AsRef<str>>(f: &Facts<'_, S>) -> Option<Relation> {
    if f.to_child {
        Some(Relation::Child)
    } else if f.to_parent {
        Some(Relation::Parent)
    } else if crate::manifest::accepts(f.accept_from, f.sender_zone, f.sender) {
        Some(Relation::Peer)
    } else if f.reply {
        Some(Relation::Reply)
    } else {
        None
    }
}

/// Why [`relation`] refused a message to `to` (its principal, or what the sender's side calls it):
/// the same words wherever it was decided.
pub fn refusal(to: &str, sender_zone: &str, sender: Option<&str>) -> String {
    match sender {
        Some(id) => format!("{to} does not accept messages from you ({id}, zone {sender_zone}): its accept_from lists neither"),
        None => format!("{to} does not accept messages from you (zone {sender_zone}): its accept_from lists neither"),
    }
}

/// Whether a message sent at `priority` by `sender` may interrupt its recipient's running turn
/// (#252): only a `now` message from someone with a say over the recipient's work, its parent
/// (`parent`, its principal) or the operator it acts for (`operator`). A turn an operator's prompt
/// started (`prompt_turn`) is the operator's: only that operator interrupts it, never the parent.
/// From anyone else a `now` message waits for the turn like a `next` one: a peer that may write to
/// an agent can't stop its work.
pub fn interrupts(priority: &str, sender: Option<&str>, parent: Option<&str>, operator: Option<&str>, prompt_turn: bool) -> bool {
    let from_operator = sender.is_some() && sender == operator;
    let from_parent = sender.is_some() && sender == parent;
    priority == "now" && (from_operator || (from_parent && !prompt_turn))
}

/// How often one sender may interrupt one recipient's turns (#252 review): at most once in this
/// many seconds, however many `now` messages it sends.
pub const INTERRUPT_EVERY_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(accept_from: &'a [&'a str]) -> Facts<'a, &'a str> {
        Facts {
            to_child: false,
            to_parent: false,
            accept_from,
            sender_zone: "za",
            sender: Some("spiffe://d/t/t0/z/za/a/alice"),
            reply: false,
        }
    }

    #[test]
    fn only_a_parent_or_its_operator_interrupts() {
        let (p, o, peer) = (Some("spiffe://d/t/t0/z/za/a/lead"), Some("spiffe://d/t/t0/op/unix/alice"), Some("spiffe://d/t/t0/z/zb/a/x"));
        assert!(interrupts("now", p, p, o, false) && interrupts("now", o, p, o, false));
        assert!(!interrupts("now", peer, p, o, false), "a peer waits for the turn");
        assert!(!interrupts("next", p, p, o, false) && !interrupts("later", o, p, o, false), "only now");
        assert!(!interrupts("now", None, None, None, false), "an unknown sender never matches no parent");
        // An operator's prompt turn is the operator's to interrupt, not the parent's.
        assert!(interrupts("now", o, p, o, true) && !interrupts("now", p, p, o, true));
    }

    #[test]
    fn family_then_accept_from_then_a_reply() {
        let none: &[&str] = &[];
        assert_eq!(relation(&Facts { to_child: true, ..facts(none) }), Some(Relation::Child));
        assert_eq!(relation(&Facts { to_parent: true, ..facts(none) }), Some(Relation::Parent));
        // Family wins over accept_from (a child is a child, whatever its zone lists).
        assert_eq!(relation(&Facts { to_child: true, ..facts(&["za"]) }), Some(Relation::Child));
        assert_eq!(relation(&facts(&["za"])), Some(Relation::Peer), "by zone");
        assert_eq!(relation(&facts(&["spiffe://d/t/t0/z/za/a/alice"])), Some(Relation::Peer), "by principal");
        assert_eq!(relation(&facts(&["zb"])), None);
        assert_eq!(relation(&Facts { reply: true, ..facts(&["zb"]) }), Some(Relation::Reply), "an answer needs no accept_from");
        assert_eq!(relation(&Facts { reply: true, ..facts(&["za"]) }), Some(Relation::Peer), "accepted anyway: a peer");
        assert_eq!(relation(&Facts { sender: None, ..facts(&["spiffe://d/t/t0/z/za/a/alice"]) }), None, "a principal needs the sender's");
    }

    #[test]
    fn one_refusal_text() {
        let r = refusal("spiffe://d/t/t0/z/zb/a/bob", "za", Some("spiffe://d/t/t0/z/za/a/alice"));
        assert_eq!(r, "spiffe://d/t/t0/z/zb/a/bob does not accept messages from you (spiffe://d/t/t0/z/za/a/alice, zone za): its accept_from lists neither");
        assert!(refusal("bob", "za", None).ends_with("(zone za): its accept_from lists neither"));
    }
}
