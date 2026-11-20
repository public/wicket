import Wicket.Host

/-!
# Zones and the decision (#322, items 1 and 2)

A zone's reach and forbid rules, its `escalation` rights and its limits, and
`CompiledZone::evaluate` (wicket-core `op.rs`): a request is forbidden if its host is never reachable
or a forbid rule matches it; otherwise it is allowed by reach if some reach rule matches its host,
method and path and allows its risk; otherwise it needs a grant.

Two inputs are computed outside the spec and carried on the op: its risk (`classify`, the
dangerous-pattern list) and whether its host is never reachable (`never_reachable`, WHATWG host
parsing). Both are pure functions of the request, the same for every zone, so neither affects which
zone allows more.
-/

namespace Wicket

structure Reach where
  host : Str
  methods : List Str
  paths : List Str
  dangerous : Bool
  /-- `decode_slash` (#664): the segments in which an encoded slash is decided as `/`. -/
  decode : List Nat := []
  deriving Repr

structure Forbid where
  host : Str
  paths : List Str
  deriving Repr

structure Escalation where
  request : Bool
  grant : Bool
  deriving Repr

/-- A zone's limits, as `Limits` reads them: byte sizes and durations already parsed (`none`: it
doesn't parse), and cpus as an exact rational scaled to an integer (an `f32` times 2^160; `none`:
not finite). Durations are in milliseconds. -/
structure Limits where
  memory : Option Nat
  cpus : Option Int
  pids : Nat
  output : Option Nat
  stopOnFull : Bool
  timeout : Option Nat
  authority : Option Nat
  deriving Repr

structure Llm where
  provider : Str
  secret : Str
  upstream : Str
  serverTools : Bool
  maxRequests : Nat
  maxOutput : Nat
  maxInput : Option Nat
  /-- `zone.llm.models` (#366): the models its boxes may call, each a name or a prefix ending in
  `*`; `none`: any. -/
  models : Option (List Str)
  deriving Repr

structure Inject where
  host : Str
  header : Str
  format : Str
  secret : Str
  deriving DecidableEq, Repr

structure Zone where
  name : Str
  /-- 1: runc, 2: gVisor. -/
  isolation : Nat
  reach : List Reach
  forbid : List Forbid
  /-- `unlisted_hosts: hide`. -/
  hide : Bool
  wildcardsForbid : Bool
  maxNames : Nat
  inject : List Inject
  llm : Option Llm
  escalation : Escalation
  limits : Limits
  acceptFrom : List Str
  deriving Repr

/-- One request, as `Op::egress` normalises it. Risk: 0 (R0) to 4 (R4). -/
structure Op where
  method : Str
  host : Str
  path : Str
  risk : Nat
  unreachable : Bool
  deriving Repr

inductive Verdict where
  | allow
  | forbidden
  | needsGrant
  deriving DecidableEq, Repr

/-- `eq_ignore_ascii_case`. -/
def methodEq (a b : Str) : Bool := lowerS a == lowerS b

def Reach.matches (r : Reach) (o : Op) : Bool :=
  hostMatches r.host o.host && r.methods.any (fun m => methodEq m o.method) &&
    r.paths.any (fun g => globB csEq g o.path)

/-- R3 and R4 are allowed by reach only with `allow_dangerous`. -/
def Reach.allows (r : Reach) (o : Op) : Bool := r.matches o && (decide (o.risk < 3) || r.dangerous)

/-- Forbid globs ignore ASCII case (#115). -/
def Forbid.matches (f : Forbid) (o : Op) : Bool :=
  hostMatches f.host o.host && f.paths.any (fun g => globB ciEq g o.path)

def Zone.forbids (z : Zone) (o : Op) : Bool := z.forbid.any (·.matches o)

def Zone.reaches (z : Zone) (o : Op) : Bool := z.reach.any (·.allows o)

def evaluate (z : Zone) (o : Op) : Verdict :=
  if o.unreachable then .forbidden
  else if z.forbids o then .forbidden
  else if z.reaches o then .allow
  else .needsGrant

/-- A canonical request path starts with `/` (`canonical_path`). -/
def AbsPath (p : Str) : Prop := p.head? = some '/'

/-! ## Forbid always wins -/

/-- **Forbid always wins**: a request any forbid rule matches is forbidden, whatever the reach
rules say. -/
theorem forbid_wins {z : Zone} {o : Op} {f : Forbid} (hf : f ∈ z.forbid) (hm : f.matches o = true) :
    evaluate z o = .forbidden := by
  have : z.forbids o = true := List.any_eq_true.mpr ⟨f, hf, hm⟩
  unfold evaluate; split <;> simp_all

theorem allow_iff {z : Zone} {o : Op} :
    evaluate z o = .allow ↔ o.unreachable = false ∧ z.forbids o = false ∧ z.reaches o = true := by
  unfold evaluate
  split <;> rename_i h1
  · simp [h1]
  · split <;> rename_i h2
    · simp [h2]
    · split <;> rename_i h3 <;> simp_all

/-- Allowed only if no forbid rule matches. -/
theorem allow_not_forbidden {z : Zone} {o : Op} (h : evaluate z o = .allow) :
    ∀ f ∈ z.forbid, f.matches o = false := by
  have := (allow_iff.mp h).2.1
  simp only [Zone.forbids, List.any_eq_false] at this
  intro f hf; simpa using this f hf

/-- Forbid rules ignore case: a request matched by a forbid rule is matched in any ASCII case. -/
theorem forbid_any_case {f : Forbid} {o : Op} (p : Str) (hp : lowerS p = lowerS o.path)
    (h : f.matches o = true) : f.matches { o with path := p } = true := by
  simp only [Forbid.matches, Bool.and_eq_true, List.any_eq_true] at h ⊢
  refine ⟨h.1, ?_⟩
  obtain ⟨g, hg, hm⟩ := h.2
  refine ⟨g, hg, ?_⟩
  have hrel : ∀ (a b : Str), lowerS a = lowerS b → CiSegs (split a) (split b) := by
    intro a b hab
    induction a generalizing b with
    | nil =>
      cases b with
      | nil => exact Forall2.refl (fun s => Forall2.refl ciEq_refl s) _
      | cons y b => simp [lowerS] at hab
    | cons x a ih =>
      cases b with
      | nil => simp [lowerS] at hab
      | cons y b =>
        simp only [lowerS, List.map_cons, List.cons.injEq] at hab
        have ihab := ih b hab.2
        have hxy : ciEq x y = true := by simp [ciEq, hab.1]
        have hx : x = '/' ↔ y = '/' := by
          constructor
          · rintro rfl
            exact eq_of_toLower_eq (d := '/') (by decide) (by rw [← hab.1]; decide)
          · rintro rfl
            exact eq_of_toLower_eq (d := '/') (by decide) (by rw [hab.1]; decide)
        simp only [split, splitAux] at ihab ⊢
        by_cases h : x = '/'
        · have h' := hx.mp h
          simp only [h, h', ite_true]
          exact .cons .nil ihab
        · have h' : ¬ y = '/' := fun e => h (hx.mpr e)
          simp only [h, h', ite_false]
          cases ihab with
          | cons h1 h2 => exact .cons (.cons hxy h1) h2
  rw [globB_iff] at hm ⊢
  unfold Lang at hm ⊢
  obtain ⟨ss, hss, hr⟩ := segsM_ci_spelling hm
  have hr' : CiSegs (split o.path) (split p) := hrel _ _ hp.symm
  exact segsM_ci_of_spelling hss (ciSegs_trans hr hr')

/-- Reach rules are a set: the decision doesn't depend on their order (or on repeats). -/
theorem evaluate_reach_set {z z' : Zone} (hf : z'.forbid = z.forbid) (hr : ∀ r, r ∈ z.reach ↔ r ∈ z'.reach)
    (o : Op) : evaluate z o = evaluate z' o := by
  have h1 : z.forbids o = z'.forbids o := by simp [Zone.forbids, hf]
  have h2 : z.reaches o = z'.reaches o := by
    apply Bool.eq_iff_iff.mpr
    simp only [Zone.reaches, List.any_eq_true]
    exact ⟨fun ⟨r, h, a⟩ => ⟨r, (hr r).mp h, a⟩, fun ⟨r, h, a⟩ => ⟨r, (hr r).mpr h, a⟩⟩
  simp [evaluate, h1, h2]

/-- Allowed at a risk, allowed at any lower risk. -/
theorem allow_lower_risk {z : Zone} {o : Op} {r : Nat} (h : evaluate z o = .allow) (hr : r ≤ o.risk) :
    evaluate z { o with risk := r } = .allow := by
  rw [allow_iff] at h ⊢
  obtain ⟨h1, h2, h3⟩ := h
  refine ⟨h1, ?_, ?_⟩
  · simpa [Zone.forbids, Forbid.matches] using h2
  · simp only [Zone.reaches, List.any_eq_true, Reach.allows, Reach.matches, Bool.and_eq_true,
      Bool.or_eq_true, decide_eq_true_eq] at h3 ⊢
    obtain ⟨x, hx, hm, hd⟩ := h3
    exact ⟨x, hx, hm, hd.imp (fun h => by omega) id⟩

end Wicket
