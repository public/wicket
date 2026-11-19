import Wicket.Zone

/-!
# Standing reach (#572)

An agent asks once for a reach rule for its workload; a human approves it, for the agent's
principal or its zone, and every later run it binds to is allowed what the rule allows, above the
zone's reach and within everything else.

- `narrow` is `wicket_core::standing::narrow`: the ask narrowed to its evidence (the blocked
  requests the rule covers, and how often each was granted). `narrow_pairs_granted`: every method
  and path pair of the narrowed rule is one a human granted; `narrow_not_dangerous`: it never allows
  R3 or R4; `narrow_allows_only_evidence`: for evidence paths without glob metacharacters, it allows
  only a request on a granted method and path, to the asked host.
- `Reach.allows` is `ReachRule::allows`, which is what a standing rule decides:
  `rule_allows_within_globs`, it allows only a path one of its globs matches.
- `Standing.binds` is `wicket_store::Standing::binds`, and `zoneDigest` its digest of a zone's
  egress (`zone_digest`): `binds_digest`, a rule binds only to a run whose zone hashes as the one it
  was approved under, and `digest_decides_alike`, for a digest that doesn't collide, every such zone
  decides every request as that one did.
-/

namespace Wicket

/-! ## Narrowing to the evidence -/

/-- One op of an ask's evidence (`EvidenceOp`): a method and path, and how often it was granted. -/
structure EvOp where
  method : Str
  path : Str
  granted : Nat
  deriving Repr

/-- The characters `glob_literal` puts in a class of their own. -/
def metaChars : List Char := ['*', '?', '[', ']', '{', '}', '\\']

/-- `standing::glob_literal(path)`: `path` as a glob that matches only itself. -/
def globLit (p : Str) : Str := p.flatMap (fun c => if c ∈ metaChars then ['[', c, ']'] else [c])

/-- `to_ascii_uppercase`. -/
def upperS (s : Str) : Str := s.map Char.toUpper

/-- Byte order (`Ord for str`; the oracle's strings are bytes, one `Char` each). -/
def strLe : Str → Str → Bool
  | [], _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a = b then strLe as bs else decide (a < b)

def sortS (l : List Str) : List Str := l.mergeSort strLe

/-- Each element once, where it first occurs. (On a sorted list: `dedup`.) -/
def nub : List Str → List Str
  | [] => []
  | a :: l => a :: (nub l).filter (· != a)

/-- One method's entry in `narrow`'s map: its method, how often it was granted, and its granted
paths as literal globs, each once, in the order they first occur. -/
structure Group where
  method : Str
  granted : Nat
  paths : List Str

def grantedOps (ops : List EvOp) : List EvOp := ops.filter (fun o => decide (0 < o.granted))

def groupOf (ops : List EvOp) (m : Str) : Group :=
  let os := (grantedOps ops).filter (fun o => o.method == m)
  { method := m, granted := (os.map (·.granted)).sum, paths := nub (os.map (fun o => globLit o.path)) }

/-- The map's entries in key order (a `BTreeMap`'s). -/
def groups (ops : List EvOp) : List Group :=
  (sortS (nub ((grantedOps ops).map (·.method)))).map (groupOf ops)

/-- `max_by_key((granted, Reverse(method)))`: the most granted, the least method among those, which
in key order is the first with the most. -/
def topGroup (gs : List Group) : Option Group :=
  let most := (gs.map (·.granted)).foldl max 0
  gs.find? (fun g => g.granted == most)

/-- `ReachRule::canonical`, for the rule `narrow` builds. -/
def canonicalRule (host : Str) (methods paths : List Str) : Reach :=
  { host := lowerS host, methods := nub (sortS (methods.map upperS)), paths := nub (sortS paths), dangerous := false }

/-- The methods `narrow` keeps: the top one, and any granted on exactly its paths. -/
def keptMethods (gs : List Group) (top : Group) : List Str :=
  (gs.filter (fun g => g.method == top.method || sortS g.paths == sortS top.paths)).map (·.method)

/-- The rule `narrow` builds from the map and its top entry: at most 16 pairs (`STANDING_PAIRS`). -/
def narrowTo (host : Str) (gs : List Group) (top : Group) : Reach :=
  let methods := keptMethods gs top
  canonicalRule host methods (top.paths.take (max (16 / methods.length) 1))

/-- `standing::narrow(host, ops)`. -/
def narrow (host : Str) (ops : List EvOp) : Option Reach :=
  (topGroup (groups ops)).map (narrowTo host (groups ops))

/-- What `narrow` returns, when it returns one. -/
theorem narrow_some {host : Str} {ops : List EvOp} {r : Reach} (h : narrow host ops = some r) :
    ∃ top, topGroup (groups ops) = some top ∧ r = narrowTo host (groups ops) top := by
  unfold narrow at h
  obtain ⟨top, ht, rfl⟩ := Option.map_eq_some_iff.mp h
  exact ⟨top, ht, rfl⟩

theorem mem_nub {x : Str} : ∀ {l : List Str}, x ∈ nub l ↔ x ∈ l
  | [] => by simp [nub]
  | a :: l => by
    simp only [nub, List.mem_cons, List.mem_filter, mem_nub (l := l), bne_iff_ne, ne_eq]
    constructor
    · rintro (h | ⟨h, _⟩) <;> simp [h]
    · rintro (h | h)
      · exact .inl h
      · by_cases e : x = a
        · exact .inl e
        · exact .inr ⟨h, e⟩

theorem mem_sortS {x : Str} {l : List Str} : x ∈ sortS l ↔ x ∈ l := List.mem_mergeSort

/-- Every path of a method's entry is the literal glob of an op granted on that method. -/
theorem mem_groupOf_paths {ops : List EvOp} {m p : Str} (h : p ∈ (groupOf ops m).paths) :
    ∃ o ∈ ops, 0 < o.granted ∧ o.method = m ∧ globLit o.path = p := by
  simp only [groupOf, mem_nub, List.mem_map, List.mem_filter, grantedOps, decide_eq_true_eq,
    beq_iff_eq] at h
  obtain ⟨o, ⟨⟨ho, hg⟩, hm⟩, hp⟩ := h
  exact ⟨o, ho, hg, hm, hp⟩

theorem mem_groups {ops : List EvOp} {g : Group} (h : g ∈ groups ops) : g = groupOf ops g.method := by
  simp only [groups, List.mem_map] at h
  obtain ⟨m, _, rfl⟩ := h
  rfl

theorem topGroup_mem {gs : List Group} {t : Group} (h : topGroup gs = some t) : t ∈ gs :=
  List.mem_of_find?_eq_some h

/-- **A narrowed rule's every pair was granted** (#572 review, M2): each of its methods, on each of
its paths, is (upper-cased) the method of an op of the evidence that a human granted, and the path
that op's path as a literal glob. One rule is every method × every path: `narrow` never pairs a
method with a path it wasn't granted on. -/
theorem narrow_pairs_granted {host : Str} {ops : List EvOp} {r : Reach} (h : narrow host ops = some r)
    {m p : Str} (hm : m ∈ r.methods) (hp : p ∈ r.paths) :
    ∃ o ∈ ops, 0 < o.granted ∧ upperS o.method = m ∧ globLit o.path = p := by
  obtain ⟨top, htop, rfl⟩ := narrow_some h
  simp only [narrowTo, keptMethods, canonicalRule, mem_nub, mem_sortS, List.mem_map, List.mem_filter,
    Bool.or_eq_true, beq_iff_eq] at hm hp
  obtain ⟨gm, ⟨g, ⟨hg, hsame⟩, rfl⟩, rfl⟩ := hm
  have hpt : p ∈ top.paths := List.mem_of_mem_take hp
  have hpg : p ∈ g.paths := by
    rcases hsame with e | e
    · have ht := mem_groups (topGroup_mem htop)
      have hg' := mem_groups hg
      rw [hg', e, ← ht]; exact hpt
    · exact mem_sortS.mp (e ▸ mem_sortS.mpr hpt)
  rw [mem_groups hg] at hpg
  obtain ⟨o, ho, hgr, hom, hop⟩ := mem_groupOf_paths hpg
  exact ⟨o, ho, hgr, by rw [hom], hop⟩

/-- A narrowed rule never allows R3 or R4 (the evidence says nothing of risk). -/
theorem narrow_not_dangerous {host : Str} {ops : List EvOp} {r : Reach} (h : narrow host ops = some r) :
    r.dangerous = false := by
  obtain ⟨top, _, rfl⟩ := narrow_some h
  rfl

/-- A narrowed rule is for the asked host. -/
theorem narrow_host {host : Str} {ops : List EvOp} {r : Reach} (h : narrow host ops = some r) :
    r.host = lowerS host := by
  obtain ⟨top, _, rfl⟩ := narrow_some h
  rfl

/-- Nothing granted, nothing to narrow to. -/
theorem narrow_none_of_ungranted {host : Str} {ops : List EvOp} (h : ∀ o ∈ ops, o.granted = 0) :
    narrow host ops = none := by
  have : grantedOps ops = [] := by
    simp only [grantedOps, List.filter_eq_nil_iff, decide_eq_true_eq]
    intro o ho; simp [h o ho]
  simp [narrow, groups, this, nub, sortS, topGroup]

/-! ## What a literal glob matches -/

/-- A path without glob metacharacters is its own literal glob. -/
theorem globLit_plain {p : Str} (h : ∀ c ∈ p, c ∉ metaChars) : globLit p = p := by
  induction p with
  | nil => rfl
  | cons c p ih =>
    simp only [globLit, List.flatMap_cons] at ih ⊢
    have hc := h c (by simp)
    simp only [hc, ite_false, List.singleton_append]
    rw [ih (fun d hd => h d (by simp [hd]))]

theorem splitAux_inj : ∀ {p q : Str}, splitAux p = splitAux q → p = q
  | [], [] => fun _ => rfl
  | [], c :: q => by
    simp only [splitAux]
    split <;> simp
  | c :: p, [] => by
    simp only [splitAux]
    split <;> simp
  | c :: p, d :: q => by
    simp only [splitAux]
    intro h
    by_cases hc : c = '/' <;> by_cases hd : d = '/' <;> simp only [hc, hd, ite_true, ite_false] at h
    · subst hc hd
      have : splitAux p = splitAux q := by
        simp only [Prod.mk.injEq, List.cons.injEq] at h
        exact Prod.ext h.2.1 h.2.2
      rw [splitAux_inj this]
    · simp at h
    · simp at h
    · simp only [Prod.mk.injEq, List.cons.injEq] at h
      obtain ⟨⟨rfl, h1⟩, h2⟩ := h
      rw [splitAux_inj (Prod.ext h1 h2)]

theorem split_inj {p q : Str} (h : split p = split q) : p = q := by
  simp only [split, List.cons.injEq] at h
  exact splitAux_inj (Prod.ext h.1 h.2)

/-- **A literal glob matches only its own path**: a glob without `*` or `?` matches exactly the path
it spells. -/
theorem plain_glob_matches_only_itself {g p : Str} (hg : g.all plainChar) (h : globB csEq g p = true) :
    p = g := by
  rw [globB_iff] at h
  unfold Lang at h
  rw [globParse_of_head (head_plain hg)] at h
  unfold parse at h
  have := (segsM_plain_append (plain_of_split hg) [] (split p)).mp (by simpa using h)
  obtain ⟨t, ht, hnil⟩ := this
  cases hnil
  exact split_inj (by simpa using ht)

theorem toUpper_toLower (c : Char) : c.toUpper.toLower = c.toLower := by
  unfold Char.toUpper Char.toLower
  by_cases h : 'a'.val ≤ c.val ∧ c.val ≤ 'z'.val
  · rw [dite_eq_left_of_eq_true (eq_true h)]
    have hn : ¬ (c.val ≥ 'A'.val ∧ c.val ≤ 'Z'.val) := by
      simp only [UInt32.le_iff_toNat_le] at h ⊢; simp at h ⊢; omega
    rw [dite_eq_right_of_eq_false (eq_false hn)]
    have hy : (c.val + ('A'.val - 'a'.val)) ≥ 'A'.val ∧ c.val + ('A'.val - 'a'.val) ≤ 'Z'.val := by
      simp only [UInt32.le_iff_toNat_le] at h ⊢
      simp [UInt32.toNat_add] at h ⊢
      omega
    rw [dite_eq_left_of_eq_true (eq_true hy)]
    apply Char.ext
    apply UInt32.toNat_inj.mp
    simp only [UInt32.le_iff_toNat_le] at h
    simp [UInt32.toNat_add] at h ⊢
    omega
  · rw [dite_eq_right_of_eq_false (eq_false h)]

theorem methodEq_upper {a b : Str} (h : methodEq (upperS a) b = true) : methodEq a b = true := by
  simpa [methodEq, lowerS, upperS, Function.comp_def, toUpper_toLower] using h

/-- **A narrowed rule allows only what was granted**: where the evidence's paths have no glob
metacharacters (canonical paths rarely do; `standing.rs`'s test covers those that do), a request
the narrowed rule allows is to the asked host, on a method and path some op of the evidence was
granted on. -/
theorem narrow_allows_only_evidence {host : Str} {ops : List EvOp} {r : Reach} (h : narrow host ops = some r)
    (hplain : ∀ o ∈ ops, ∀ c ∈ o.path, c ∉ metaChars) {q : Op} (ha : r.allows q = true) :
    hostMatches host q.host = true ∧ ∃ o ∈ ops, 0 < o.granted ∧ methodEq o.method q.method = true ∧ o.path = q.path := by
  simp only [Reach.allows, Reach.matches, Bool.and_eq_true, List.any_eq_true] at ha
  obtain ⟨⟨⟨hh, m, hm, hme⟩, g, hg, hgm⟩, _⟩ := ha
  refine ⟨?_, ?_⟩
  · rw [narrow_host h] at hh
    simpa [hostMatches, lowerS_lowerS] using hh
  · obtain ⟨o, ho, hgr, hom, hop⟩ := narrow_pairs_granted h hm hg
    have hpl := hplain o ho
    rw [globLit_plain hpl] at hop
    subst hop hom
    have : o.path.all plainChar := by
      simp only [List.all_eq_true, plainChar]
      intro c hc
      have := hpl c hc
      simp only [metaChars, List.mem_cons, not_or] at this
      simp [this.1, this.2.1]
    exact ⟨o, ho, hgr, methodEq_upper hme, (plain_glob_matches_only_itself this hgm).symm⟩

/-! ## A rule allows only what its globs match -/

/-- **A standing rule covers only paths its globs match**: what `ReachRule::allows` decides is its
host, one of its methods, a path one of its globs matches (in the spec's language), and a risk below
R3 unless it has `allow_dangerous`. -/
theorem rule_allows_within_globs {r : Reach} {q : Op} :
    r.allows q = true ↔ hostMatches r.host q.host = true ∧ (∃ m ∈ r.methods, methodEq m q.method = true) ∧
      (∃ g ∈ r.paths, Lang csEq g q.path) ∧ (q.risk < 3 ∨ r.dangerous = true) := by
  simp only [Reach.allows, Reach.matches, Bool.and_eq_true, List.any_eq_true, globB_iff, Bool.or_eq_true,
    decide_eq_true_eq, and_assoc]

/-! ## Binding to a zone's definition -/

/-- What a standing rule is for: the asking agent's principal, or its zone. -/
inductive Bound where
  | agent
  | zone
  deriving DecidableEq, Repr

/-- The part of a zone a standing rule binds to (`zone_digest`'s subset): what decides egress. -/
structure Egress where
  reach : List Reach
  forbid : List Forbid
  inject : List Inject
  hide : Bool
  wildcardsForbid : Bool
  maxNames : Nat
  escalation : Escalation

def Zone.egress (z : Zone) : Egress :=
  { reach := z.reach, forbid := z.forbid, inject := z.inject, hide := z.hide,
    wildcardsForbid := z.wildcardsForbid, maxNames := z.maxNames, escalation := z.escalation }

/-- `zone_digest(zone)`: a hash (`H`) of the zone's egress subset. -/
def zoneDigest {D : Type} (H : Egress → D) (z : Zone) : D := H z.egress

/-- An approved standing rule, as `binds` reads it. -/
structure Standing (D : Type) where
  principal : Str
  zone : Str
  digest : D
  bound : Option Bound

/-- `Standing::binds(principal, zone, zone_digest)`. -/
def Standing.binds {D : Type} [DecidableEq D] (s : Standing D) (principal : Option Str) (zone : Str) (digest : D) : Bool :=
  decide (digest = s.digest) &&
    match s.bound with
    | some .agent => principal == some s.principal
    | some .zone => zone == s.zone
    | none => false

/-- A rule binds only with the zone definition it was approved under, and only to the principal or
zone it was approved for. -/
theorem binds_digest {D : Type} [DecidableEq D] {s : Standing D} {p : Option Str} {z : Str} {d : D}
    (h : s.binds p z d = true) :
    d = s.digest ∧ ((s.bound = some .agent ∧ p = some s.principal) ∨ (s.bound = some .zone ∧ z = s.zone)) := by
  unfold Standing.binds at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  refine ⟨h.1, ?_⟩
  have h2 := h.2
  split at h2
  · rename_i hb; exact .inl ⟨hb, by simpa using h2⟩
  · rename_i hb; exact .inr ⟨hb, by simpa using h2⟩
  · simp at h2

/-- **A rule binds only where the zone decides as it did** (#572 review, M1): for a digest that
doesn't collide, a zone hashing as the one a rule was approved under has its reach, forbids,
injections and the rest of its egress, so it decides every request as that one did. (Edits outside
the subset, a timeout or a model budget, keep the rule.) -/
theorem digest_decides_alike {D : Type} {H : Egress → D} (hinj : ∀ a b, H a = H b → a = b) {z z₀ : Zone}
    (h : zoneDigest H z = zoneDigest H z₀) : z.egress = z₀.egress ∧ ∀ o, evaluate z o = evaluate z₀ o := by
  have he := hinj _ _ h
  refine ⟨he, fun o => ?_⟩
  have hr : z.reach = z₀.reach := congrArg Egress.reach he
  have hf : z.forbid = z₀.forbid := congrArg Egress.forbid he
  simp [evaluate, Zone.forbids, Zone.reaches, hr, hf]

end Wicket
