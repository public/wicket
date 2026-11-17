import Wicket.Zone

/-!
# Authority only narrows: `subset.rs` (#322, item 1)

`subset::check` admits a spawned zone only if it can prove it within its parent's, and
`subset::reach_within` decides the same for links. This file restates them step for step
(`pathCovered` is `path_covered`, `cover` its `segments_cover` table, `segCovers` its
`segment_covers`) and proves:

- `pathCovered_sound`: a covered child glob matches no path its parent's globs don't;
- `reach_sound`, `forbid_kept`: a child admitted by the reach check is allowed by reach nothing its
  parent isn't, and forbids everything its parent forbids;
- `check_within`: a child admitted by `check` is `Within` its parent: reach, forbid, escalation,
  isolation, limits, credential injections and the model route all narrow;
- `within_trans`, `grandchild_within`: narrowing composes.

Image admission (`image::matching`, by digest, #192) is outside this spec: the case carries its
answer (`Bounds.imagesOk`).
-/

namespace Wicket

/-! ## Paths -/

/-- Glob metacharacters, and `\`. -/
def META : List Char := ['*', '?', '[', '{', '\\']

def hasMeta (s : Str) : Bool := s.any (· ∈ META)

/-- The child's text before its first metacharacter. -/
def literalPart (c : Str) : Str := c.takeWhile (fun x => x ∉ META)

def dropSuffix? (s suf : Str) : Option Str :=
  if suf.isSuffixOf s then some (s.take (s.length - suf.length)) else none

def globstarSuffix : Str := ['/', '*', '*']

/-- `segments`: an absolute glob's segments after the leading `/`. -/
def segsOf : Str → Option (List Seg)
  | '/' :: b => some (parse b)
  | _ => none

theorem segsOf_eq {g : Str} {P : List Seg} (h : segsOf g = some P) : ∃ b, g = '/' :: b ∧ P = parse b := by
  unfold segsOf at h
  split at h
  · cases h; exact ⟨_, rfl, rfl⟩
  · cases h

/-- `segment_covers`. -/
def segCovers (p c : Str) : Bool :=
  p == c || (!c.any (· ∈ ['[', '{', '\\']) && (p == ['*'] || (!hasMeta c && tokB csEq (toks p) c)))

/-- `segments_cover`'s table, `ok[i][j]`, as a recursion on the suffixes. -/
def cover : List Seg → List Seg → Bool
  | [], cs => cs.isEmpty
  | .one _ :: _, [] => false
  | .one _ :: _, .any :: _ => false
  | .one p :: ps, .one c :: cs => segCovers p c && cover ps cs
  | .any :: [], cs => !cs.isEmpty
  | .any :: (q :: ps), [] => cover (q :: ps) []
  | .any :: (q :: ps), c :: cs => cover (q :: ps) (c :: cs) || cover (.any :: q :: ps) cs

def segsCover (g c : Str) : Bool :=
  match segsOf g, segsOf c with
  | some P, some C => cover P C
  | _, _ => false

/-- `path_covered(parent, child)`. -/
def pathCovered (ps : List Str) (c : Str) : Bool :=
  ps.any (fun g => g == c || g == globstarSuffix) ||
    (if !hasMeta c then ps.any (fun g => globB csEq g c)
     else ps.any (fun g => match dropSuffix? g globstarSuffix with
       | some q => (!hasMeta q && (q ++ ['/']).isPrefixOf (literalPart c)) || segsCover g c
       | none => segsCover g c))

/-- The segments of a canonical path: an empty one before the leading `/`, then at least one. -/
def AbsSegs (ss : List Str) : Prop := ∃ t, ss = [] :: t ∧ t ≠ []

theorem absSegs_of_absPath {p : Str} (h : AbsPath p) : AbsSegs (split p) := by
  cases p with
  | nil => simp [AbsPath] at h
  | cons x b =>
    simp [AbsPath] at h
    subst h
    exact ⟨split b, split_cons_slash b, split_ne_nil b⟩

theorem all_plain_of_not_hasMeta {c : Str} (h : hasMeta c = false) : c.all plainChar := by
  simp only [hasMeta, List.any_eq_false, META] at h
  simp only [List.all_eq_true, plainChar]
  intro x hx
  have := h x hx
  simp_all

theorem segCovers_sound {p c s : Str} (h : segCovers p c = true) (hc : TokM csEq (toks c) s) :
    TokM csEq (toks p) s := by
  simp only [segCovers, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true, Bool.not_eq_true',
    List.any_eq_false] at h
  rcases h with rfl | ⟨_, rfl | ⟨hm, ht⟩⟩
  · exact hc
  · exact tokM_star_any csEq s
  · rw [toks_plain (all_plain_of_not_hasMeta hm), tokM_lits_iff] at hc
    subst hc
    exact (tokB_iff _ _ _).mp ht

/-- A non-trailing parent `**` covers a child `**` whose rest it covers. -/
theorem any_absorb {P cs : List Seg} (hP : P ≠ [])
    (hcs : ∀ t, SegsM csEq cs t → SegsM csEq (.any :: P) t) :
    ∀ ss, SegsM csEq (.any :: cs) ss → SegsM csEq (.any :: P) ss := by
  intro ss h
  generalize hL : Seg.any :: cs = L at h
  induction h with
  | nil => cases hL
  | one _ _ => cases hL
  | @anyLast ss hne =>
    cases hL
    have h0 := hcs [] .nil
    simpa using SegsM.eat_all hP h0 ss
  | anySkip _ h _ => cases hL; exact hcs _ h
  | anyEat _ _ ih => cases hL; exact .anyEat hP (ih rfl)

theorem cover_sound : ∀ (P C : List Seg), cover P C = true → ∀ ss, SegsM csEq C ss → SegsM csEq P ss := by
  intro P
  induction P with
  | nil =>
    intro C hc ss h
    cases C with
    | nil => exact h
    | cons _ _ => simp [cover] at hc
  | cons p P ih =>
    cases p with
    | one p =>
      intro C hc ss h
      cases C with
      | nil => simp [cover] at hc
      | cons c C =>
        cases c with
        | any => simp [cover] at hc
        | one c =>
          simp only [cover, Bool.and_eq_true] at hc
          cases h with
          | one ht h => exact .one (segCovers_sound hc.1 ht) (ih C hc.2 _ h)
    | any =>
      cases P with
      | nil =>
        intro C hc ss h
        simp only [cover, Bool.not_eq_true', List.isEmpty_eq_false_iff] at hc
        exact .anyLast (h.ne_nil hc)
      | cons q P =>
        intro C
        induction C with
        | nil =>
          intro hc ss h
          simp only [cover] at hc
          cases h
          exact .anySkip (by simp) (ih [] hc [] .nil)
        | cons c C ihC =>
          intro hc ss h
          simp only [cover, Bool.or_eq_true] at hc
          rcases hc with hc | hc
          · exact .anySkip (by simp) (ih _ hc _ h)
          · have hcs := ihC hc
            cases c with
            | one c =>
              cases h with
              | one _ h => exact .anyEat (by simp) (hcs _ h)
            | any => exact any_absorb (by simp) hcs _ h

theorem dropSuffix?_eq {s suf q : Str} (h : dropSuffix? s suf = some q) : s = q ++ suf := by
  unfold dropSuffix? at h
  split at h
  · rename_i hs
    cases h
    rw [List.isSuffixOf_iff_suffix] at hs
    exact (List.suffix_iff_eq_append.mp hs).symm
  · cases h

theorem parse_append_slash (a b : Str) : parse (a ++ '/' :: b) = parse a ++ parse b := by
  simp [parse, split_append_slash]

theorem parse_globstar (q : Str) : parse (q ++ globstarSuffix) = parse q ++ [.any] := by
  rw [globstarSuffix, parse_append_slash]
  rfl

/-- **`path_covered` is sound**: on a canonical path, a covered child glob matches nothing none of
the parent's globs match. -/
theorem pathCovered_sound {ps : List Str} {c : Str} (hcov : pathCovered ps c = true) :
    ∀ ss, AbsSegs ss → SegsM csEq (globParse c) ss → ∃ g ∈ ps, SegsM csEq (globParse g) ss := by
  intro ss habs hm
  unfold pathCovered at hcov
  simp only [Bool.or_eq_true, List.any_eq_true, beq_iff_eq] at hcov
  rcases hcov with ⟨g, hg, rfl | rfl⟩ | hcov
  · exact ⟨g, hg, hm⟩
  · refine ⟨_, hg, ?_⟩
    obtain ⟨t, rfl, ht⟩ := habs
    rw [show globParse globstarSuffix = [.one [], .any] by decide]
    exact .one .nil (.anyLast ht)
  · split at hcov
    · rename_i hmeta
      simp only [Bool.not_eq_eq_eq_not, Bool.not_true] at hmeta
      obtain ⟨g, hg, hgm⟩ := List.any_eq_true.mp hcov
      have hplain := plain_of_split (all_plain_of_not_hasMeta hmeta)
      rw [globParse_of_head (head_plain (all_plain_of_not_hasMeta hmeta))] at hm
      have := (segsM_plain_append hplain [] ss).mp (by simpa [parse] using hm)
      obtain ⟨t, rfl, ht⟩ := this
      cases ht
      have h2 := (globB_iff _ _ _).mp hgm
      unfold Lang at h2
      exact ⟨g, hg, by simpa using h2⟩
    · obtain ⟨g, hg, hgm⟩ := List.any_eq_true.mp hcov
      refine ⟨g, hg, ?_⟩
      have viaSegs : segsCover g c = true → SegsM csEq (globParse g) ss := by
        intro hsc
        unfold segsCover at hsc
        split at hsc
        · rename_i P C hP hC
          obtain ⟨gb, rfl, rfl⟩ := segsOf_eq hP
          obtain ⟨cb, rfl, rfl⟩ := segsOf_eq hC
          have hpc : parse ('/' :: cb) = .one [] :: parse cb := by
            simp [parse, split_cons_slash, parseSeg]
          have hpg : parse ('/' :: gb) = .one [] :: parse gb := by
            simp [parse, split_cons_slash, parseSeg]
          rw [globParse_of_head (by simp [split_cons_slash, globstar]), hpc] at hm
          rw [globParse_of_head (by simp [split_cons_slash, globstar]), hpg]
          cases hm with
          | one h0 hrest => exact .one h0 (cover_sound _ _ hsc _ hrest)
        · simp at hsc
      split at hgm
      · rename_i q hq
        simp only [Bool.or_eq_true, Bool.and_eq_true, Bool.not_eq_true'] at hgm
        rcases hgm with ⟨hqm, hpre⟩ | hsc
        · have hg' := dropSuffix?_eq hq
          rw [List.isPrefixOf_iff_prefix] at hpre
          obtain ⟨rest, hrest⟩ := hpre.trans (List.takeWhile_prefix _)
          have hc : c = q ++ '/' :: rest := by rw [← hrest]; simp
          have hqh := head_plain (all_plain_of_not_hasMeta hqm)
          rw [hc, globParse_of_head (by rw [head_split_append]; exact hqh), parse_append_slash] at hm
          have hqplain := plain_of_split (all_plain_of_not_hasMeta hqm)
          obtain ⟨t, rfl, ht⟩ := (segsM_plain_append hqplain _ ss).mp hm
          rw [hg', globParse_of_head (by rw [globstarSuffix, head_split_append]; exact hqh), parse_globstar]
          have hne : parse rest ≠ [] := by simp [parse, split_ne_nil]
          exact (segsM_plain_append hqplain _ _).mpr ⟨t, rfl, .anyLast (ht.ne_nil hne)⟩
        · exact viaSegs hsc
      · exact viaSegs hgm

/-- The same, for forbid globs, which ignore case. -/
theorem pathCovered_sound_ci {ps : List Str} {c p : Str} (hcov : pathCovered ps c = true)
    (hp : AbsPath p) (hm : Lang ciEq c p) : ∃ g ∈ ps, Lang ciEq g p := by
  obtain ⟨ss, hss, hr⟩ := segsM_ci_spelling hm
  have habs : AbsSegs ss := by
    obtain ⟨t, ht, hne⟩ := absSegs_of_absPath hp
    rw [ht] at hr
    cases hr with
    | cons h0 hrest =>
      cases h0
      exact ⟨_, rfl, CiSegs.ne_nil hrest hne⟩
  obtain ⟨g, hg, hgm⟩ := pathCovered_sound hcov ss habs hss
  exact ⟨g, hg, segsM_ci_of_spelling hgm hr⟩

/-! ## Reach and forbid: `reach_violations` -/

def ruleCovered (p : Zone) (r : Reach) (m path : Str) : Bool :=
  p.reach.any (fun q => hostCovers q.host r.host && q.methods.any (fun qm => methodEq qm m) &&
    pathCovered q.paths path && (!r.dangerous || q.dangerous))

def reachCovered (p c : Zone) : Bool :=
  c.reach.all (fun r => r.methods.all (fun m => r.paths.all (fun path => ruleCovered p r m path)))

def forbidKept (p c : Zone) : Bool :=
  p.forbid.all (fun f => f.paths.all (fun fp =>
    c.forbid.any (fun g => hostCovers g.host f.host && pathCovered g.paths fp)))

def injectKept (p c : Zone) : Bool := c.inject.all (fun i => p.inject.contains i)

/-- `reach_violations(p, c)` is empty. -/
def reachOk (p c : Zone) : Bool :=
  !(p.hide && !c.hide) && !(p.wildcardsForbid && !c.wildcardsForbid) && decide (c.maxNames ≤ p.maxNames) &&
    reachCovered p c && forbidKept p c && injectKept p c

/-- `reach_within(outer, inner)` (links, design §4.3). -/
def reachWithin (outer inner : Zone) : Bool :=
  reachOk outer inner && !(inner.llm.isSome && outer.llm.isNone)

theorem methodEq_trans {a b c : Str} (h1 : methodEq a b = true) (h2 : methodEq b c = true) :
    methodEq a c = true := by
  simp only [methodEq, beq_iff_eq] at *; rw [h1, h2]

/-- Every parent forbid binds the child: what the parent forbids (by a rule), the child forbids. -/
theorem forbid_kept {p c : Zone} (h : forbidKept p c = true) {o : Op} (hp : AbsPath o.path)
    (hf : p.forbids o = true) : c.forbids o = true := by
  simp only [Zone.forbids, List.any_eq_true, Forbid.matches, Bool.and_eq_true] at hf ⊢
  obtain ⟨f, hfm, hh, fp, hfp, hpm⟩ := hf
  simp only [forbidKept, List.all_eq_true, List.any_eq_true, Bool.and_eq_true] at h
  obtain ⟨g, hg, hgh, hgp⟩ := h f hfm fp hfp
  obtain ⟨g', hg', hm⟩ := pathCovered_sound_ci hgp hp ((globB_iff _ _ _).mp hpm)
  exact ⟨g, hg, hostCovers_sound hgh hh, g', hg', (globB_iff _ _ _).mpr hm⟩

theorem reach_covered {p c : Zone} (h : reachCovered p c = true) {o : Op} (hp : AbsPath o.path)
    (hr : c.reaches o = true) : p.reaches o = true := by
  simp only [Zone.reaches, List.any_eq_true, Reach.allows, Reach.matches, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at hr ⊢
  obtain ⟨r, hrm, ⟨⟨hh, hmeth⟩, hpath⟩, hrisk⟩ := hr
  obtain ⟨m, hm, hmo⟩ := hmeth
  obtain ⟨g, hg, hgm⟩ := hpath
  simp only [reachCovered, List.all_eq_true] at h
  have := h r hrm m hm g hg
  simp only [ruleCovered, List.any_eq_true, Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true'] at this
  obtain ⟨q, hq, ⟨⟨hqh, hqm⟩, hqp⟩, hqd⟩ := this
  obtain ⟨qm, hqm1, hqm2⟩ := hqm
  obtain ⟨g', hg', hm'⟩ := pathCovered_sound hqp _ (absSegs_of_absPath hp) ((globB_iff csEq g o.path).mp hgm)
  refine ⟨q, hq, ⟨⟨hostCovers_sound hqh hh, ⟨qm, hqm1, methodEq_trans hqm2 hmo⟩⟩,
    ⟨g', hg', (globB_iff csEq g' o.path).mpr hm'⟩⟩, ?_⟩
  rcases hrisk with h | h
  · exact Or.inl h
  · rcases hqd with hd | hd
    · simp [hd] at h
    · exact Or.inr hd

/-- **A child admitted by the reach check is allowed by reach nothing its parent isn't.** -/
theorem reach_sound {p c : Zone} (h : reachOk p c = true) {o : Op} (hp : AbsPath o.path)
    (hc : evaluate c o = .allow) : evaluate p o = .allow := by
  simp only [reachOk, Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨⟨_, _⟩, _⟩, hreach⟩, hforbid⟩, _⟩ := h
  rw [allow_iff] at hc ⊢
  obtain ⟨hu, hf, hr⟩ := hc
  refine ⟨hu, ?_, reach_covered hreach hp hr⟩
  cases hpf : p.forbids o
  · rfl
  · rw [forbid_kept hforbid hp hpf] at hf; cases hf

/-- **And forbids everything its parent forbids.** -/
theorem forbidden_sound {p c : Zone} (h : reachOk p c = true) {o : Op} (hp : AbsPath o.path)
    (hpf : evaluate p o = .forbidden) : evaluate c o = .forbidden := by
  simp only [reachOk, Bool.and_eq_true] at h
  obtain ⟨⟨_, hforbid⟩, _⟩ := h
  unfold evaluate at hpf ⊢
  split
  · rfl
  · rename_i hu
    split at hpf
    · contradiction
    · split at hpf
      · rename_i hfo; simp [forbid_kept hforbid hp hfo]
      · split at hpf <;> cases hpf

/-! ## The whole check: `subset::check` -/

/-- `MIN_CPUS` (0.01 as an `f32`: 10737418 × 2^-30), times 2^160. -/
def minCpus : Int := 10737418 * 2 ^ 130

/-- What the constructing agent has (`Bounds`). Durations in milliseconds. -/
structure Bounds where
  zone : Zone
  /-- `image::matching` of the ask's image, and of each of its zone's images, against the agent's. -/
  imagesOk : Bool
  llmRemaining : Option (Nat × Nat)
  llmInputRemaining : Option Nat
  timeRemaining : Nat
  childSlots : Nat

structure Ask where
  zone : Zone
  maxChildren : Nat

def llmOk (c : Zone) (b : Bounds) : Bool :=
  match c.llm, b.zone.llm with
  | none, _ => true
  | some _, none => false
  | some cl, some pl =>
    cl.provider == pl.provider && cl.secret == pl.secret && cl.upstream == pl.upstream &&
      !(cl.serverTools && !pl.serverTools) &&
      (match b.llmRemaining with
       | none => true
       | some (r, t) => decide (cl.maxRequests ≤ r) && decide (cl.maxOutput ≤ t)) &&
      (match cl.maxInput, b.llmInputRemaining with
       | _, none => true
       | none, some _ => false
       | some n, some left => decide (n ≤ left))

def sizeOk : Option Nat → Option Nat → Bool
  | some c, some p => decide (1 ≤ c ∧ c ≤ p)
  | _, _ => false

def limitsOk (c p : Limits) (timeRemaining : Nat) : Bool :=
  sizeOk c.memory p.memory &&
    (match c.cpus, p.cpus with
     | some cc, some pc => decide (minCpus ≤ cc ∧ cc ≤ pc)
     | _, _ => false) &&
    sizeOk c.output p.output &&
    !(p.stopOnFull && !c.stopOnFull) &&
    decide (1 ≤ c.pids ∧ c.pids ≤ p.pids) &&
    (match c.timeout with
     | some t => decide (t ≠ 0 ∧ t ≤ timeRemaining)
     | none => false) &&
    (match c.authority, p.authority with
     | some ca, some pa => decide (ca ≤ pa)
     | _, _ => false)

/-! ### The model allowlist (#366) -/

/-- `str::starts_with`: `s` starts with `p`. -/
def startsWith : Str → Str → Bool
  | [], [] => true
  | [], _ :: _ => false
  | _ :: _, [] => true
  | a :: s, b :: p => a == b && startsWith s p

/-- `pattern.strip_suffix('*')`: the prefix a pattern ending in `*` stands for. -/
def stripStar : Str → Option Str
  | [] => none
  | [c] => if c = '*' then some [] else none
  | c :: d :: s =>
    match stripStar (d :: s) with
    | some r => some (c :: r)
    | none => none

/-- `manifest::model_covers(pattern, other)`: a prefix pattern covers what starts with its prefix,
a name only itself. -/
def modelCovers (q m : Str) : Bool :=
  match stripStar q with
  | some p => startsWith m p
  | none => q == m

/-- `LlmSpec::allows_model`. -/
def Llm.allowsModel (l : Llm) (n : Str) : Bool :=
  match l.models with
  | none => true
  | some ms => ms.any (fun q => modelCovers q n)

/-- `model_violations(c, p)` is empty: with a parent list, the child has one, each entry covered by
one of the parent's. -/
def llmModelsOk (cl pl : Llm) : Bool :=
  match pl.models with
  | none => true
  | some pm =>
    match cl.models with
    | none => false
    | some cm => cm.all (fun m => pm.any (fun q => modelCovers q m))

/-- The model part of `check`'s route check (both zones have a route). -/
def modelsOk (c p : Zone) : Bool :=
  match c.llm, p.llm with
  | some cl, some pl => llmModelsOk cl pl
  | _, _ => true

def acceptOk (c p : Zone) : Bool := c.acceptFrom.all (fun z => z == p.name || p.acceptFrom.contains z)

def escalationOk (c p : Escalation) : Bool := !(c.request && !p.request) && !(c.grant && !p.grant)

/-- `subset::check(ask, parent)` is `Ok`. -/
def check (a : Ask) (b : Bounds) : Bool :=
  let c := a.zone
  let p := b.zone
  decide (p.isolation ≤ c.isolation) && reachOk p c && llmOk c b && limitsOk c.limits p.limits b.timeRemaining &&
    b.imagesOk && acceptOk c p && escalationOk c.escalation p.escalation && decide (a.maxChildren < b.childSlots) &&
    modelsOk c p

/-! ## Within: what narrowing means -/

def OptLe {α} [LE α] : Option α → Option α → Prop
  | some a, some b => a ≤ b
  | _, _ => False

theorem OptLe.trans {α} [LE α] (htr : ∀ x y z : α, x ≤ y → y ≤ z → x ≤ z) {a b c : Option α}
    (h1 : OptLe a b) (h2 : OptLe b c) : OptLe a c := by
  match a, b, c, h1, h2 with
  | some _, some _, some _, h1, h2 => exact htr _ _ _ h1 h2

/-- A zone `c` is within `p`: on every canonical request it is allowed by reach only what `p` is,
and forbids what `p` forbids; it has no right, injection, route or resource `p` lacks. -/
structure Within (c p : Zone) : Prop where
  reach : ∀ o : Op, AbsPath o.path → evaluate c o = .allow → evaluate p o = .allow
  forbid : ∀ o : Op, AbsPath o.path → evaluate p o = .forbidden → evaluate c o = .forbidden
  request : c.escalation.request = true → p.escalation.request = true
  grant : c.escalation.grant = true → p.escalation.grant = true
  isolation : p.isolation ≤ c.isolation
  hide : p.hide = true → c.hide = true
  wildcards : p.wildcardsForbid = true → c.wildcardsForbid = true
  maxNames : c.maxNames ≤ p.maxNames
  inject : ∀ i ∈ c.inject, i ∈ p.inject
  llm : ∀ cl, c.llm = some cl → ∃ pl, p.llm = some pl ∧ cl.provider = pl.provider ∧
    cl.secret = pl.secret ∧ cl.upstream = pl.upstream ∧ (cl.serverTools = true → pl.serverTools = true)
  memory : OptLe c.limits.memory p.limits.memory
  cpus : OptLe c.limits.cpus p.limits.cpus
  output : OptLe c.limits.output p.limits.output
  stop : p.limits.stopOnFull = true → c.limits.stopOnFull = true
  pids : c.limits.pids ≤ p.limits.pids
  authority : OptLe c.limits.authority p.limits.authority

/-- **Narrowing composes.** -/
theorem within_trans {g c p : Zone} (h1 : Within g c) (h2 : Within c p) : Within g p where
  reach o ho h := h2.reach o ho (h1.reach o ho h)
  forbid o ho h := h1.forbid o ho (h2.forbid o ho h)
  request h := h2.request (h1.request h)
  grant h := h2.grant (h1.grant h)
  isolation := Nat.le_trans h2.isolation h1.isolation
  hide h := h1.hide (h2.hide h)
  wildcards h := h1.wildcards (h2.wildcards h)
  maxNames := Nat.le_trans h1.maxNames h2.maxNames
  inject i hi := h2.inject i (h1.inject i hi)
  llm gl hg := by
    obtain ⟨cl, hc, e1, e2, e3, e4⟩ := h1.llm gl hg
    obtain ⟨pl, hp, f1, f2, f3, f4⟩ := h2.llm cl hc
    exact ⟨pl, hp, e1.trans f1, e2.trans f2, e3.trans f3, fun h => f4 (e4 h)⟩
  memory := OptLe.trans (fun _ _ _ => Nat.le_trans) h1.memory h2.memory
  cpus := OptLe.trans (fun _ _ _ => Int.le_trans) h1.cpus h2.cpus
  output := OptLe.trans (fun _ _ _ => Nat.le_trans) h1.output h2.output
  stop h := h1.stop (h2.stop h)
  pids := Nat.le_trans h1.pids h2.pids
  authority := OptLe.trans (fun _ _ _ => Nat.le_trans) h1.authority h2.authority

/-- **A spawned zone admitted by `subset::check` is within its parent's.** -/
theorem check_within {a : Ask} {b : Bounds} (h : check a b = true) : Within a.zone b.zone := by
  simp only [check, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨hiso, hreach⟩, hllm⟩, hlim⟩, _⟩, _⟩, hesc⟩, _⟩, _⟩ := h
  have hr := hreach
  simp only [reachOk, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at hr
  obtain ⟨⟨⟨⟨⟨hhide, hwild⟩, hnames⟩, _⟩, _⟩, hinj⟩ := hr
  simp only [escalationOk, Bool.and_eq_true, Bool.not_eq_true'] at hesc
  simp only [limitsOk, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at hlim
  obtain ⟨⟨⟨⟨⟨⟨hmem, hcpu⟩, hout⟩, hstop⟩, hpids⟩, _⟩, hauth⟩ := hlim
  have size : ∀ {x y : Option Nat}, sizeOk x y = true → OptLe x y := by
    intro x y h
    match x, y, h with
    | some _, some _, h => simp [sizeOk] at h; exact h.2
  refine ⟨fun o ho hc => reach_sound hreach ho hc, fun o ho hc => forbidden_sound hreach ho hc, ?_, ?_, hiso,
    ?_, ?_, hnames, ?_, ?_, size hmem, ?_, size hout, ?_, hpids.2, ?_⟩
  · intro hc; cases hp : b.zone.escalation.request <;> simp_all
  · intro hc; cases hp : b.zone.escalation.grant <;> simp_all
  · intro hp; cases hc : a.zone.hide <;> simp_all
  · intro hp; cases hc : a.zone.wildcardsForbid <;> simp_all
  · simp only [injectKept, List.all_eq_true, List.contains_iff_mem] at hinj
    exact hinj
  · intro cl hcl
    unfold llmOk at hllm
    rw [hcl] at hllm
    revert hllm
    match b.zone.llm with
    | none => simp
    | some pl =>
      intro hllm
      simp only [Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at hllm
      refine ⟨pl, rfl, ?_, ?_, ?_, fun h => ?_⟩
      · exact hllm.1.1.1.1.1
      · exact hllm.1.1.1.1.2
      · exact hllm.1.1.1.2
      · have := hllm.1.1.2
        cases hps : pl.serverTools <;> simp_all
  · match a.zone.limits.cpus, b.zone.limits.cpus, hcpu with
    | some _, some _, h => simp only [decide_eq_true_eq] at h; exact h.2
    | none, _, h => simp at h
    | some _, none, h => simp at h
  · intro hp; cases hc : a.zone.limits.stopOnFull <;> simp_all
  · match a.zone.limits.authority, b.zone.limits.authority, hauth with
    | some _, some _, h => simpa [OptLe] using h
    | none, _, h => simp at h
    | some _, none, h => simp at h

/-- **A grandchild stays within its grandparent's authority**: two admitted spawns compose. -/
theorem grandchild_within {a1 a2 : Ask} {b1 b2 : Bounds} (h1 : check a1 b1 = true) (h2 : check a2 b2 = true)
    (hb : b2.zone = a1.zone) : Within a2.zone b1.zone :=
  within_trans (hb ▸ check_within h2) (check_within h1)

/-- A link's target admitted by `reach_within` reaches nothing its connector can't. -/
theorem reachWithin_sound {outer inner : Zone} (h : reachWithin outer inner = true) {o : Op}
    (hp : AbsPath o.path) (hi : evaluate inner o = .allow) : evaluate outer o = .allow := by
  simp only [reachWithin, Bool.and_eq_true] at h
  exact reach_sound h.1 hp hi

end Wicket
