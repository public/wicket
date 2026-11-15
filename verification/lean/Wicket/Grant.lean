import Wicket.Subset

/-!
# Grants stay within their granter's authority (#322, item 1; #291, #311, #320)

`grant::decide` as an agent decides it (`Granter::Agent`): `within_authority` (the request is a
descendant's, the granter's zone has `escalation.grant`, it is one HTTP path, the granter's own
zone allows it by reach at the request's risk, and its org layer doesn't refuse it), `check_terms`
and `agent_terms` (to the asking run only, exactly the asked path, a number of uses, ending no later
than the granter's own authority). And an operator's authority (`operators.yaml`, #320).

Proved (`agent_grant_within`): every use the grant permits is one the granter could make itself by
reach, by a strict descendant, within the granter's lifetime, for a bounded number of uses; with
`grant_within_ancestor`, the same holds for every zone the granter's is within (narrowing composes).

What the spec takes as given (pure functions of the request, the same for every granter): the risk
`classify` gives a request, `never_reachable`, wicket's reserved namespace, and whether a request is a
git push (`git::grant_terms`). The ledger's identities are a parent function.
-/

namespace Wicket

/-- A pending request, as the ledger holds it (method upper-cased, host canonical). -/
structure Request where
  tenant : Str
  run : Str
  method : Str
  host : Str
  path : Str
  scopePrefix : Bool
  /-- `RiskClass::from_name(req.risk)`'s rank; `none`: unknown. -/
  risk : Option Nat

/-- What an approval grants (`Terms`); `ttl` in seconds. -/
structure Terms where
  uses : Option Nat
  ttl : Nat
  pfx : Option Str
  zoneWide : Bool

structure Env where
  parentOf : Str → Option Str
  classify : Str → Str → Str → Nat
  unreachable : Str → Bool
  reserved : Str → Str → Bool
  gitPush : Str → Str → Bool

/-- An agent run's own authority (`AgentAuthority`): `until` (`authEnd`) in Unix seconds. -/
structure AgentAuthority where
  tenant : Str
  run : Str
  zone : Zone
  /-- `OrgLayer::refuses_http(host, method, path, risk)`. -/
  orgRefuses : Str → Str → Str → Nat → Bool
  authEnd : Nat

def httpMethods : List Str := ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].map String.toList

def maxChain : Nat := 64

def maxTtl : Nat := 24 * 3600

/-- `descendant_chain`'s loop: up the parents from `at`, the chain so far `chain`. -/
def walk (parentOf : Str → Option Str) (target : Str) : Nat → List Str → Option Str → Option (List Str)
  | 0, _, _ => none
  | n + 1, chain, some p =>
    if p = target then some (chain ++ [p])
    else if chain.length < maxChain ∧ p ∉ chain then walk parentOf target n (chain ++ [p]) (parentOf p)
    else none
  | _ + 1, _, none => none

def descendantChain (parentOf : Str → Option Str) (target run : Str) : Option (List Str) :=
  walk parentOf target (maxChain + 1) [run] (parentOf run)

/-- The op `within_authority` decides, at the request's risk. -/
def Request.op (env : Env) (req : Request) (r : Nat) : Op :=
  { method := req.method, host := req.host, path := req.path,
    risk := max (env.classify req.method req.host req.path) r, unreachable := env.unreachable req.host }

/-- `within_authority(l, a, req)` is `Ok`. -/
def withinAuthority (env : Env) (a : AgentAuthority) (req : Request) : Bool :=
  req.tenant == a.tenant && (descendantChain env.parentOf a.run req.run).isSome && a.zone.escalation.grant &&
    httpMethods.contains req.method && !req.scopePrefix && !env.reserved req.method req.host &&
    match req.risk with
    | none => false
    | some r =>
      let o := req.op env r
      !a.orgRefuses o.host o.method o.path o.risk && evaluate a.zone o == .allow

/-- `check_terms` for an exact-path request (the prefix checks are a human's: `agent_terms`
refuses a prefix). -/
def checkTerms (t : Terms) : Bool := decide (0 < t.ttl ∧ t.ttl ≤ maxTtl) && t.uses != some 0

/-- `agent_terms` (and `outlasts`), at time `now`. -/
def agentTerms (env : Env) (a : AgentAuthority) (req : Request) (t : Terms) (now : Nat) : Bool :=
  !t.zoneWide && t.pfx.isNone && t.uses.isSome && !env.gitPush req.method req.path &&
    decide (now < a.authEnd ∧ now + t.ttl ≤ a.authEnd)

/-- An agent's approval of `req` with `t` at `now` goes through `decide`. -/
def agentApproves (env : Env) (a : AgentAuthority) (req : Request) (t : Terms) (now : Nat) : Bool :=
  withinAuthority env a req && checkTerms t && agentTerms env a req t now

/-- A grant row. -/
structure Grant where
  /-- `none`: any run of the zone. -/
  run : Option Str
  method : Str
  host : Str
  path : Str
  pfx : Bool
  uses : Option Nat
  expires : Nat
  maxRisk : Nat

/-- What `approve` makes of a run-scoped, exact-path approval (`Ledger::approve`: the grant's risk
bound is the request's). -/
def grantOf (req : Request) (t : Terms) (now : Nat) : Grant :=
  { run := if t.zoneWide then none else some req.run, method := req.method, host := req.host,
    path := req.path, pfx := t.pfx.isSome || req.scopePrefix, uses := t.uses, expires := now + t.ttl,
    maxRisk := req.risk.getD 0 }

/-- A request `o` of run `run` at time `now` is one the grant permits. -/
structure Grant.Permits (g : Grant) (run : Str) (o : Op) (now : Nat) : Prop where
  run : g.run = none ∨ g.run = some run
  method : o.method = g.method
  host : o.host = g.host
  path : g.pfx = false → o.path = g.path
  risk : o.risk ≤ g.maxRisk
  live : now < g.expires

/-- A request as wicket builds it: its host's reachability is the environment's. -/
def WellFormed (env : Env) (o : Op) : Prop := o.unreachable = env.unreachable o.host

/-- `r` is a strict descendant of `a`: `a` is reached from `r` by one or more parent steps. -/
inductive Desc (parentOf : Str → Option Str) (a : Str) : Str → Prop where
  | parent {r} : parentOf r = some a → Desc parentOf a r
  | step {r m} : parentOf r = some m → Desc parentOf a m → Desc parentOf a r

theorem walk_desc {parentOf : Str → Option Str} {target : Str} :
    ∀ n chain (r : Str) ch, walk parentOf target n chain (parentOf r) = some ch → Desc parentOf target r := by
  intro n
  induction n with
  | zero => intro _ _ _ h; simp [walk] at h
  | succ n ih =>
    intro chain r ch h
    cases hp : parentOf r with
    | none => rw [hp] at h; simp [walk] at h
    | some p =>
      rw [hp] at h
      simp only [walk] at h
      split at h
      · rename_i e; subst e; exact .parent hp
      · split at h
        · exact .step hp (ih _ p ch h)
        · cases h

/-- The chain is only found for a strict descendant. -/
theorem descendantChain_desc {parentOf : Str → Option Str} {target run : Str} {ch : List Str}
    (h : descendantChain parentOf target run = some ch) : Desc parentOf target run :=
  walk_desc _ _ _ _ h

/-- With no cycles among the ledger's identities, an agent never decides its own request. -/
theorem not_own {parentOf : Str → Option Str} {a r : Str} (hacyc : ∀ x, ¬ Desc parentOf x x)
    (h : Desc parentOf a r) : r ≠ a := by
  rintro rfl; exact hacyc _ h

/-- **A grant within `within_authority` is a subset of its granter's authority.** Every use the
grant an agent makes permits is one its own zone allows by reach, by a strict descendant (the asking
run), before the agent's own authority ends, for a bounded number (at least one) of uses; and the
granter's org layer didn't refuse it at the request's risk. -/
theorem agent_grant_within {env : Env} {a : AgentAuthority} {req : Request} {t : Terms} {now : Nat}
    (h : agentApproves env a req t now = true) :
    let g := grantOf req t now
    (∀ run o now', g.Permits run o now' → WellFormed env o →
      evaluate a.zone o = .allow ∧ run = req.run ∧ o.path = req.path) ∧
    Desc env.parentOf a.run req.run ∧ g.expires ≤ a.authEnd ∧ (∃ u, g.uses = some u ∧ 1 ≤ u) ∧
    ∃ r, req.risk = some r ∧ a.orgRefuses req.host req.method req.path (max (env.classify req.method req.host req.path) r) = false := by
  simp only [agentApproves, withinAuthority, checkTerms, agentTerms, Bool.and_eq_true, beq_iff_eq,
    Option.isSome_iff_exists, decide_eq_true_eq, Bool.not_eq_true', Option.isNone_iff_eq_none, bne_iff_ne,
    ne_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨_, ch, hch⟩, _⟩, _⟩, hsp⟩, _⟩, hrisk⟩, _, hu0⟩, ⟨⟨⟨hzw, hpfx⟩, hus⟩, _⟩, hlive, hend⟩ := h
  cases hr : req.risk with
  | none => rw [hr] at hrisk; cases hrisk
  | some r =>
    rw [hr] at hrisk
    simp only [Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq] at hrisk
    obtain ⟨horg, hev⟩ := hrisk
    obtain ⟨u, hu⟩ := hus
    refine ⟨?_, descendantChain_desc hch, by simp [grantOf]; omega, ⟨u, by simp [grantOf, hu], ?_⟩, r, rfl, horg⟩
    · intro run o now' hp hw
      have hpfx' : (grantOf req t now).pfx = false := by simp [grantOf, hpfx, hsp]
      have hpath := hp.path hpfx'
      have hm := hp.method
      have hh := hp.host
      have hrk := hp.risk
      have hrn := hp.run
      simp only [grantOf, hzw, hr, Option.getD_some, Bool.false_eq_true, ite_false] at hpath hm hh hrk hrn
      have hrun : run = req.run := by
        rcases hrn with h | h
        · simp at h
        · simp at h; exact h.symm
      refine ⟨?_, hrun, hpath⟩
      have heq : o = { req.op env r with risk := o.risk } := by
        cases o
        simp only [Request.op, WellFormed] at *
        subst hm hh hpath hw
        rfl
      rw [heq]
      apply allow_lower_risk hev
      simp only [Request.op]
      omega
    · rcases u with _ | u
      · simp [hu] at hu0
      · omega

/-- With an org layer that allows at a risk whatever it allows at a higher one, the grant's every
use is also one the org layer allows. (An org `http` alternative with `min_risk` is not such a layer:
it can allow a request at the asked risk and refuse it at a lower one. The token's own org checks
still apply at each use, so this is no widening, only a check made at one risk.) -/
theorem agent_grant_org {env : Env} {a : AgentAuthority} {req : Request} {t : Terms} {now : Nat}
    (h : agentApproves env a req t now = true)
    (hmono : ∀ host m p r r', r' ≤ r → a.orgRefuses host m p r = false → a.orgRefuses host m p r' = false) :
    ∀ run o now', (grantOf req t now).Permits run o now' → WellFormed env o →
      a.orgRefuses o.host o.method o.path o.risk = false := by
  intro run o now' hp hw
  obtain ⟨_, _, _, _, r, hr, horg⟩ := agent_grant_within h
  have hpfx : (grantOf req t now).pfx = false := by
    simp only [agentApproves, agentTerms, withinAuthority, Bool.and_eq_true, Bool.not_eq_true',
      Option.isNone_iff_eq_none] at h
    simp [grantOf, h.2.1.1.1.2, h.1.1.1.1.2]
  have hpath := hp.path hpfx
  have hmeth := hp.method
  have hhost := hp.host
  have hrisk := hp.risk
  simp only [grantOf, hr, Option.getD_some] at hpath hmeth hhost hrisk
  rw [hpath, hmeth, hhost]
  exact hmono _ _ _ _ _ (by omega) horg

/-- **Narrowing composes, for grants too**: an agent's grant is within every zone the agent's own is
within (its parent's, its grandparent's, …). -/
theorem grant_within_ancestor {env : Env} {a : AgentAuthority} {req : Request} {t : Terms} {now : Nat}
    {anc : Zone} (h : agentApproves env a req t now = true) (hw : Within a.zone anc) :
    ∀ run o now', (grantOf req t now).Permits run o now' → WellFormed env o → AbsPath o.path →
      evaluate anc o = .allow := by
  intro run o now' hp hwf habs
  exact hw.reach o habs ((agent_grant_within h).1 run o now' hp hwf).1

/-- A renewal by an agent (`agent_renews`, `outlasts`) never ends past the agent's own authority. -/
def agentRenewEndOk (a : AgentAuthority) (now newEnd : Nat) : Bool := decide (now < a.authEnd ∧ newEnd ≤ a.authEnd)

theorem agent_renewal_within {a : AgentAuthority} {now newEnd : Nat} (h : agentRenewEndOk a now newEnd = true) :
    newEnd ≤ a.authEnd := by
  simp [agentRenewEndOk] at h; exact h.2

/-! ## Operators (#320) -/

inductive OpAuthority where
  | anything
  | nothing
  | scoped (kinds : List Str) (hosts : List Str) (maxRisk : Option Nat)

/-- What a decision is on (`Asked`). -/
structure Asked where
  kind : Str
  host : Str
  risk : Option Nat

/-- `Operator::may_decide`. -/
def mayDecide : OpAuthority → Asked → Bool
  | .anything, _ => true
  | .nothing, _ => false
  | .scoped kinds hosts maxRisk, a =>
    kinds.contains a.kind &&
      (a.kind != "http".toList || hosts.isEmpty || hosts.any (fun h => hostMatches h a.host)) &&
      match maxRisk with
      | none => true
      | some m => match a.risk with
        | some r => decide (r ≤ m)
        | none => a.kind == "authority".toList

theorem nothing_decides_nothing (a : Asked) : mayDecide .nothing a = false := rfl

/-- **An operator decides only within its authority**: its kinds, its hosts (for HTTP requests) and
up to its risk. -/
theorem operator_within {kinds hosts : List Str} {maxRisk : Option Nat} {a : Asked}
    (h : mayDecide (.scoped kinds hosts maxRisk) a = true) :
    a.kind ∈ kinds ∧
      (a.kind = "http".toList → hosts = [] ∨ ∃ p ∈ hosts, hostMatches p a.host = true) ∧
      (∀ m, maxRisk = some m → ∀ r, a.risk = some r → r ≤ m) := by
  simp only [mayDecide, Bool.and_eq_true, List.contains_iff_mem, Bool.or_eq_true, bne_iff_ne, ne_eq,
    List.isEmpty_iff, List.any_eq_true] at h
  obtain ⟨⟨hk, hh⟩, hr⟩ := h
  refine ⟨hk, fun e => ?_, fun m hm r hrr => ?_⟩
  · rcases hh with (h | h) | h
    · exact absurd e h
    · exact Or.inl h
    · exact Or.inr h
  · subst hm
    simp only [hrr, decide_eq_true_eq] at hr
    exact hr

end Wicket
