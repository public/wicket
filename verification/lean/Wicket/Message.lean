import Wicket.Spawn

/-!
# Who may send whom a message (#565)

`wicket_core::message::relation`: one rule, decided where a message is sent, by the control host
(`RunCtx::send`) and, while the box's node is cut off from it, by the node (`nodegw::send_local`).
Family first (the receiver is the sender's child or parent), then the receiver's `accept_from`, then
an answer to a message the receiver sent.

Both sides call the one function on the facts they hold, so on the same facts they decide alike
(`relation` is a function of `Facts`). They can differ only in what they know: a side that doesn't
know the sender's principal decides as if it had none, and `less_known_allows_no_more` proves that
lets through nothing the side that knows would refuse. `peer_iff` is when a peer is accepted:
`accept_from` names its zone (a zone entry) or its principal (a principal entry).
-/

namespace Wicket

/-- `message::Facts`: what the sender's side knows of a message's two ends. -/
structure Facts where
  toChild : Bool
  toParent : Bool
  acceptFrom : List Str
  senderZone : Str
  sender : Option Str
  reply : Bool
  deriving Repr

inductive Relation where
  | child
  | parent
  | peer
  | reply
  deriving DecidableEq, Repr

/-- `message::relation(facts)`: `none` is refused. -/
def relation (f : Facts) : Option Relation :=
  if f.toChild then some .child
  else if f.toParent then some .parent
  else if accepts f.acceptFrom f.senderZone f.sender then some .peer
  else if f.reply then some .reply
  else none

/-- **A peer is accepted only when `accept_from` names it**: as a peer exactly when it is neither
child nor parent and an entry of the receiver's `accept_from` is its zone (a zone entry) or its
principal (a principal entry, which needs the principal known). -/
theorem peer_iff {f : Facts} :
    relation f = some .peer ↔ f.toChild = false ∧ f.toParent = false ∧
      ∃ e ∈ f.acceptFrom, (isPrincipalEntry e = true ∧ f.sender = some e) ∨
        (isPrincipalEntry e = false ∧ e = f.senderZone) := by
  unfold relation accepts
  cases f.toChild <;> cases f.toParent <;> simp only [Bool.false_eq_true, ite_true, ite_false,
    reduceCtorEq, false_and, and_false, Option.some.injEq, true_and]
  constructor
  · intro h
    split at h
    · rename_i ha
      obtain ⟨e, he, hm⟩ := List.any_eq_true.mp ha
      refine ⟨e, he, ?_⟩
      cases hp : isPrincipalEntry e <;> simp [hp] at hm
      · exact .inr ⟨rfl, hm⟩
      · exact .inl ⟨rfl, hm⟩
    · split at h <;> simp at h
  · rintro ⟨e, he, h⟩
    have : (f.acceptFrom.any fun a => if isPrincipalEntry a = true then f.sender == some a else a == f.senderZone) = true := by
      refine List.any_eq_true.mpr ⟨e, he, ?_⟩
      rcases h with ⟨hp, hs⟩ | ⟨hp, hz⟩
      · simp [hp, hs]
      · subst hz; simp [hp]
    simp [this]

/-- Refused exactly when it is to neither child nor parent, `accept_from` doesn't name the sender,
and it answers nothing the receiver sent. -/
theorem refused_iff {f : Facts} :
    relation f = none ↔ f.toChild = false ∧ f.toParent = false ∧
      accepts f.acceptFrom f.senderZone f.sender = false ∧ f.reply = false := by
  unfold relation
  cases f.toChild <;> cases f.toParent <;> cases accepts f.acceptFrom f.senderZone f.sender <;>
    cases f.reply <;> simp

/-- An empty `accept_from` lets in no peer: only family and answers. -/
theorem no_peer_without_accept_from {f : Facts} (h : f.acceptFrom = []) : relation f ≠ some .peer := by
  simp [peer_iff, h]

/-- **Knowing less lets through no more** (#257): a side that doesn't know the sender's principal
(a node cut off from the control host) decides as one that does, or refuses where it accepts; never
the other way round. -/
theorem less_known_allows_no_more {f : Facts} (h : relation { f with sender := none } ≠ none) :
    relation f ≠ none := by
  have hacc : accepts f.acceptFrom f.senderZone none = true → accepts f.acceptFrom f.senderZone f.sender = true := by
    simp only [accepts, List.any_eq_true]
    rintro ⟨e, he, hm⟩
    refine ⟨e, he, ?_⟩
    cases hp : isPrincipalEntry e <;> simp [hp] at hm ⊢
    exact hm
  intro hn
  apply h
  rw [refused_iff] at hn ⊢
  obtain ⟨h1, h2, h3, h4⟩ := hn
  refine ⟨h1, h2, ?_, h4⟩
  cases ha : accepts f.acceptFrom f.senderZone none
  · rfl
  · exact absurd (hacc ha) (by simp [h3])

/-- And where both accept, the one that knows less decides the same relation, unless it can only
see an answer where the other sees a named peer. -/
theorem less_known_same_relation {f : Facts} {r : Relation} (h : relation { f with sender := none } = some r) :
    relation f = some r ∨ (r = .reply ∧ relation f = some .peer) := by
  have hacc : accepts f.acceptFrom f.senderZone none = true → accepts f.acceptFrom f.senderZone f.sender = true := by
    simp only [accepts, List.any_eq_true]
    rintro ⟨e, he, hm⟩
    refine ⟨e, he, ?_⟩
    cases hp : isPrincipalEntry e <;> simp [hp] at hm ⊢
    exact hm
  obtain ⟨c, p, af, z, s, rp⟩ := f
  simp only [relation] at h hacc ⊢
  cases c <;> cases p <;> simp only [ite_true, ite_false, Bool.false_eq_true] at h ⊢
  · cases ha : accepts af z none <;> cases hb : accepts af z s <;>
      simp only [ha, hb, ite_true, ite_false, Bool.false_eq_true] at h hacc ⊢
    · exact .inl h
    · cases rp <;> simp at h; subst h; exact .inr ⟨rfl, trivial⟩
    · exact absurd hacc (by simp)
    · exact .inl h
  · exact .inl h
  · exact .inl h
  · exact .inl h

end Wicket
