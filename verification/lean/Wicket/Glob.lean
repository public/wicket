/-!
# Path globs: the spec's language of paths (#322, item 2)

The path globs of reach and forbid rules, as `wicket_core::manifest::compile_glob` builds them
(globset with `literal_separator`), restricted to the spec's language: literal characters, `*`, `?`
and `**` segments. Classes (`[…]`), alternations (`{…}`) and escapes (`\`) are outside it: the oracle
reports them as unsupported rather than guess (`Glob.supported`).

A glob and a path are compared segment by segment, both split at `/`:
- a segment pattern matches one path segment: a literal matches itself, `?` any one character and
  `*` any run of characters (a segment has no `/`, so neither ever crosses one);
- a `**` segment matches any number of whole segments, and at least one at the end of a glob
  (`/a/**` matches `/a/` and `/a/b/c`, never `/a`).

`SegsM` is the declarative language; `segsB` the executable matcher the oracle runs. They agree
(`segsB_iff`), and the string-level consequences are proved: without `**` a match has exactly as many
`/` as the glob (`no_globstar_same_slashes`), and `Q/**` matches every path under `Q/`
(`globstar_crosses`).
-/

namespace Wicket

abbrev Str := List Char

/-! ## Splitting at `/` -/

/-- The first segment and the rest. -/
def splitAux : Str → Str × List Str
  | [] => ([], [])
  | c :: cs =>
    let r := splitAux cs
    if c = '/' then ([], r.1 :: r.2) else (c :: r.1, r.2)

/-- A string split at every `/` (never empty: `""` is `[""]`, `"/"` is `["", ""]`). -/
def split (p : Str) : List Str := (splitAux p).1 :: (splitAux p).2

theorem split_ne_nil (p : Str) : split p ≠ [] := by simp [split]

theorem split_cons_slash (b : Str) : split ('/' :: b) = [] :: split b := by
  simp [split, splitAux]

theorem splitAux_append_slash (a b : Str) :
    splitAux (a ++ '/' :: b) = ((splitAux a).1, (splitAux a).2 ++ split b) := by
  induction a with
  | nil => simp [splitAux, split]
  | cons c a ih =>
    simp only [List.cons_append, splitAux, ih]
    split <;> simp

theorem split_append_slash (a b : Str) : split (a ++ '/' :: b) = split a ++ split b := by
  simp [split, splitAux_append_slash]

/-- Every character of a segment is a character of the string. -/
theorem mem_of_mem_split {p s : Str} {x : Char} (hs : s ∈ split p) (hx : x ∈ s) : x ∈ p := by
  induction p generalizing s with
  | nil => simp [split, splitAux] at hs; subst hs; simp at hx
  | cons c p ih =>
    simp only [split, splitAux] at hs
    split at hs
    · simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · simp at hx
      · exact List.mem_cons_of_mem _ (ih (by simp only [split, List.mem_cons]; exact hs) hx)
    · simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · rcases List.mem_cons.mp hx with rfl | hx
        · exact List.mem_cons_self
        · exact List.mem_cons_of_mem _ (ih (by simp [split]) hx)
      · exact List.mem_cons_of_mem _ (ih (by simp only [split, List.mem_cons]; exact Or.inr hs) hx)

/-- No segment contains `/`. -/
theorem slash_not_mem_split {p s : Str} (hs : s ∈ split p) : '/' ∉ s := by
  induction p generalizing s with
  | nil => simp [split, splitAux] at hs; subst hs; simp
  | cons c p ih =>
    simp only [split, splitAux] at hs
    split at hs
    · simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · simp
      · exact ih (by simp only [split, List.mem_cons]; exact hs)
    · rename_i hc
      simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · intro h
        rcases List.mem_cons.mp h with h | h
        · exact hc h.symm
        · exact ih (by simp [split]) h
      · exact ih (by simp only [split, List.mem_cons]; exact Or.inr hs)

/-- There is one more segment than there are `/`. -/
theorem length_split (p : Str) : (split p).length = p.count '/' + 1 := by
  induction p with
  | nil => simp [split, splitAux]
  | cons c p ih =>
    simp only [split, splitAux] at ih ⊢
    split
    · rename_i h; subst h; simp at ih ⊢; omega
    · rename_i h; simp [h] at ih ⊢; omega

/-! ## Patterns -/

inductive Tok where
  | lit (c : Char)
  | star
  | qm
  deriving DecidableEq, Repr

def tokOf (c : Char) : Tok :=
  if c = '*' then .star else if c = '?' then .qm else .lit c

/-- A segment pattern's tokens. (`a**b` is two stars, as globset reads it.) -/
def toks (s : Str) : List Tok := s.map tokOf

/-- A glob segment: `**` on its own, or one segment's pattern (its text). -/
inductive Seg where
  | any
  | one (s : Str)
  deriving DecidableEq, Repr

def parseSeg (s : Str) : Seg := if s = ['*', '*'] then .any else .one s

def parse (g : Str) : List Seg := (split g).map parseSeg

/-- Characters the spec's language leaves out (`[`, `]`, `{`, `}`, `\`). -/
def unsupportedChars : List Char := ['[', ']', '{', '}', '\\']

def supported (g : Str) : Bool := g.all (fun c => c ∉ unsupportedChars)

/-! ## The language (declarative) -/

/-- Characters compared case-sensitively (reach globs) or ignoring ASCII case (forbid globs). -/
abbrev CharEq := Char → Char → Bool

def csEq : CharEq := fun a b => a == b
def ciEq : CharEq := fun a b => a.toLower == b.toLower

/-- One segment pattern matches one segment. -/
inductive TokM (eq : CharEq) : List Tok → Str → Prop where
  | nil : TokM eq [] []
  | lit {c x ts s} : eq c x = true → TokM eq ts s → TokM eq (.lit c :: ts) (x :: s)
  | qm {x ts s} : TokM eq ts s → TokM eq (.qm :: ts) (x :: s)
  | starNil {ts s} : TokM eq ts s → TokM eq (.star :: ts) s
  | starCons {x ts s} : TokM eq (.star :: ts) s → TokM eq (.star :: ts) (x :: s)

/-- A glob's segments match a path's segments. -/
inductive SegsM (eq : CharEq) : List Seg → List Str → Prop where
  | nil : SegsM eq [] []
  | one {p s ps ss} : TokM eq (toks p) s → SegsM eq ps ss → SegsM eq (.one p :: ps) (s :: ss)
  /-- A trailing `**`: one or more segments. -/
  | anyLast {ss} : ss ≠ [] → SegsM eq [.any] ss
  /-- `**` elsewhere: zero segments, … -/
  | anySkip {ps ss} : ps ≠ [] → SegsM eq ps ss → SegsM eq (.any :: ps) ss
  /-- … or one more. -/
  | anyEat {ps s ss} : ps ≠ [] → SegsM eq (.any :: ps) ss → SegsM eq (.any :: ps) (s :: ss)

/-- The spec's language of a glob: the paths it matches. -/
def Lang (eq : CharEq) (g p : Str) : Prop := SegsM eq (parse g) (split p)

/-! ## The executable matcher -/

def tokB (eq : CharEq) : List Tok → Str → Bool
  | [], s => s.isEmpty
  | .lit _ :: _, [] => false
  | .lit c :: ts, x :: s => eq c x && tokB eq ts s
  | .qm :: _, [] => false
  | .qm :: ts, _ :: s => tokB eq ts s
  | .star :: ts, [] => tokB eq ts []
  | .star :: ts, x :: s => tokB eq ts (x :: s) || tokB eq (.star :: ts) s

def segsB (eq : CharEq) : List Seg → List Str → Bool
  | [], ss => ss.isEmpty
  | .one _ :: _, [] => false
  | .one p :: ps, s :: ss => tokB eq (toks p) s && segsB eq ps ss
  | .any :: [], ss => !ss.isEmpty
  | .any :: (q :: ps), [] => segsB eq (q :: ps) []
  | .any :: (q :: ps), s :: ss => segsB eq (q :: ps) (s :: ss) || segsB eq (.any :: q :: ps) ss

def globB (eq : CharEq) (g p : Str) : Bool := segsB eq (parse g) (split p)

theorem tokM_star_nil {eq ts} : TokM eq (.star :: ts) [] ↔ TokM eq ts [] := by
  constructor
  · intro h; cases h; assumption
  · exact .starNil

theorem tokB_iff (eq : CharEq) (ts : List Tok) (s : Str) : tokB eq ts s = true ↔ TokM eq ts s := by
  induction ts generalizing s with
  | nil =>
    cases s with
    | nil => simp [tokB]; exact .nil
    | cons x s => simp [tokB]; intro h; cases h
  | cons t ts ih =>
    cases t with
    | lit c =>
      cases s with
      | nil => simp [tokB]; intro h; cases h
      | cons x s =>
        simp [tokB, ih]
        constructor
        · intro ⟨h1, h2⟩; exact .lit h1 h2
        · intro h; cases h; constructor <;> assumption
    | qm =>
      cases s with
      | nil => simp [tokB]; intro h; cases h
      | cons x s =>
        simp [tokB, ih]
        constructor
        · exact .qm
        · intro h; cases h; assumption
    | star =>
      induction s with
      | nil => simp [tokB, ih, tokM_star_nil]
      | cons x s ihs =>
        simp only [tokB, Bool.or_eq_true, ih, ihs]
        constructor
        · rintro (h | h)
          · exact .starNil h
          · exact .starCons h
        · intro h
          cases h with
          | starNil h => exact Or.inl h
          | starCons h => exact Or.inr h

theorem segsB_iff (eq : CharEq) (ps : List Seg) (ss : List Str) :
    segsB eq ps ss = true ↔ SegsM eq ps ss := by
  induction ps generalizing ss with
  | nil =>
    cases ss with
    | nil => simp [segsB]; exact .nil
    | cons s ss => simp [segsB]; intro h; cases h
  | cons p ps ih =>
    cases p with
    | one p =>
      cases ss with
      | nil => simp [segsB]; intro h; cases h
      | cons s ss =>
        simp [segsB, ih, tokB_iff]
        constructor
        · intro ⟨h1, h2⟩; exact .one h1 h2
        · intro h; cases h; constructor <;> assumption
    | any =>
      cases ps with
      | nil =>
        simp [segsB]
        constructor
        · intro h; exact .anyLast h
        · intro h
          cases h with
          | anyLast h => exact h
          | anySkip h => exact absurd rfl h
          | anyEat h => exact absurd rfl h
      | cons q ps =>
        induction ss with
        | nil =>
          simp only [segsB, ih]
          constructor
          · exact .anySkip (by simp)
          · intro h; cases h with
            | anySkip _ h => exact h
        | cons s ss ihs =>
          simp only [segsB, Bool.or_eq_true, ih, ihs]
          constructor
          · rintro (h | h)
            · exact .anySkip (by simp) h
            · exact .anyEat (by simp) h
          · intro h
            cases h with
            | anySkip _ h => exact Or.inl h
            | anyEat _ h => exact Or.inr h

theorem globB_iff (eq : CharEq) (g p : Str) : globB eq g p = true ↔ Lang eq g p :=
  segsB_iff eq _ _

/-! ## Facts about the language -/

/-- A pattern with segments matches only a non-empty list of segments. -/
theorem SegsM.ne_nil {eq ps ss} (h : SegsM eq ps ss) (hp : ps ≠ []) : ss ≠ [] := by
  induction h with
  | nil => exact absurd rfl hp
  | one _ _ => simp
  | anyLast h => exact h
  | anySkip hne _ ih => exact ih hne
  | anyEat _ _ _ => simp

/-- A non-trailing `**` absorbs any segments in front of a match. -/
theorem SegsM.eat_all {eq ps ss} (hp : ps ≠ []) (h : SegsM eq (.any :: ps) ss) :
    ∀ u, SegsM eq (.any :: ps) (u ++ ss) := by
  intro u
  induction u with
  | nil => simpa using h
  | cons x u ih => exact .anyEat hp ih

/-- `*` matches any segment. -/
theorem tokM_star_any (eq : CharEq) (s : Str) : TokM eq [.star] s := by
  induction s with
  | nil => exact .starNil .nil
  | cons x s ih => exact .starCons ih

/-- Characters that aren't `*` or `?`: their pattern is exactly the literals. -/
def plainChar (c : Char) : Bool := c ≠ '*' && c ≠ '?'

theorem toks_plain {s : Str} (h : s.all plainChar) : toks s = s.map Tok.lit := by
  induction s with
  | nil => rfl
  | cons c s ih =>
    simp [List.all_cons, plainChar] at h
    simp [toks, tokOf, h.1.1, h.1.2] at ih ⊢
    exact ih (by simpa [List.all_eq_true, plainChar] using h.2)

/-- A literal pattern matches exactly its own text (case-sensitively). -/
theorem tokM_lits_iff (s x : Str) : TokM csEq (s.map Tok.lit) x ↔ x = s := by
  induction s generalizing x with
  | nil =>
    constructor
    · intro h; cases h; rfl
    · rintro rfl; exact .nil
  | cons c s ih =>
    constructor
    · intro h
      cases h with
      | lit hc h => simp [csEq] at hc; subst hc; rw [(ih _).mp h]
    · rintro rfl; exact .lit (by simp [csEq]) ((ih _).mpr rfl)

theorem parseSeg_plain {s : Str} (h : s.all plainChar) : parseSeg s = .one s := by
  unfold parseSeg
  split
  · subst_vars; simp [plainChar] at h
  · rfl

/-- A glob without `*` or `?`, followed by more segments, matches its own segments first. -/
theorem segsM_plain_append {qs : List Str} (hq : ∀ s ∈ qs, s.all plainChar) (R : List Seg)
    (ss : List Str) : SegsM csEq (qs.map parseSeg ++ R) ss ↔ ∃ t, ss = qs ++ t ∧ SegsM csEq R t := by
  induction qs generalizing ss with
  | nil => simp
  | cons q qs ih =>
    have hq0 := hq q (by simp)
    have hrest : ∀ s ∈ qs, s.all plainChar := fun s hs => hq s (by simp [hs])
    simp only [List.map_cons, List.cons_append, parseSeg_plain hq0]
    constructor
    · intro h
      cases h with
      | one ht h =>
        rw [toks_plain hq0, tokM_lits_iff] at ht
        subst ht
        obtain ⟨t, rfl, ht⟩ := (ih hrest _).mp h
        exact ⟨t, rfl, ht⟩
    · rintro ⟨t, rfl, ht⟩
      exact .one (by rw [toks_plain hq0, tokM_lits_iff]) ((ih hrest _).mpr ⟨t, rfl, ht⟩)

theorem plain_of_split {q : Str} (h : q.all plainChar) : ∀ s ∈ split q, s.all plainChar := by
  intro s hs
  simp only [List.all_eq_true] at h ⊢
  intro x hx
  exact h x (mem_of_mem_split hs hx)

/-- **`*` stays within a segment.** A glob without a `**` segment matches only paths with exactly
as many `/` as it has: no `*` or `?` ever matches a `/`. -/
theorem no_globstar_same_slashes {eq g p} (hg : ∀ s ∈ split g, s ≠ ['*', '*']) (h : Lang eq g p) :
    p.count '/' = g.count '/' := by
  have : ∀ ps ss, (∀ x ∈ ps, x ≠ Seg.any) → SegsM eq ps ss → ss.length = ps.length := by
    intro ps ss hps h
    induction h with
    | nil => rfl
    | one _ _ ih => simp only [List.length_cons, ih (fun x hx => hps x (by simp [hx]))]
    | anyLast _ => exact absurd rfl (hps _ (by simp))
    | anySkip _ _ _ => exact absurd rfl (hps _ (by simp))
    | anyEat _ _ _ => exact absurd rfl (hps _ (by simp))
  have hno : ∀ x ∈ parse g, x ≠ Seg.any := by
    intro x hx
    simp only [parse, List.mem_map] at hx
    obtain ⟨s, hs, rfl⟩ := hx
    unfold parseSeg; split
    · exact absurd ‹_› (hg s hs)
    · simp
  have := this _ _ hno h
  simp only [parse, List.length_map, length_split] at this
  omega

/-- **`**` crosses segments.** `Q/**`, for a `Q` without `*` or `?`, matches `Q/` followed by
anything, `/` included. -/
theorem globstar_crosses {q : Str} (hq : q.all plainChar) (w : Str) :
    Lang csEq (q ++ ['/', '*', '*']) (q ++ '/' :: w) := by
  unfold Lang parse
  rw [split_append_slash, split_append_slash]
  have hs : split ['*', '*'] = [['*', '*']] := by decide
  rw [hs, List.map_append]
  simp only [List.map_cons, List.map_nil]
  have : parseSeg ['*', '*'] = .any := by decide
  rw [this]
  exact (segsM_plain_append (plain_of_split hq) _ _).mpr ⟨_, rfl, .anyLast (split_ne_nil w)⟩

/-! ## Ignoring case: a match ignoring case is a case-sensitive match of a same-case spelling -/

inductive Forall2 {α β} (R : α → β → Prop) : List α → List β → Prop where
  | nil : Forall2 R [] []
  | cons {a b as bs} : R a b → Forall2 R as bs → Forall2 R (a :: as) (b :: bs)

theorem Forall2.refl {α} {R : α → α → Prop} (h : ∀ a, R a a) : ∀ l, Forall2 R l l
  | [] => .nil
  | a :: l => .cons (h a) (Forall2.refl h l)

abbrev CiRel (s y : Str) : Prop := Forall2 (fun a b => ciEq a b = true) s y

theorem ciEq_refl (a : Char) : ciEq a a = true := by simp [ciEq]

theorem ciEq_trans {a b c : Char} (h1 : ciEq a b = true) (h2 : ciEq b c = true) : ciEq a c = true := by
  simp [ciEq] at *; rw [h1, h2]

theorem tokM_ci_spelling {ts y} (h : TokM ciEq ts y) : ∃ s, TokM csEq ts s ∧ CiRel s y := by
  induction h with
  | nil => exact ⟨[], .nil, .nil⟩
  | @lit c x _ _ hc _ ih =>
    obtain ⟨s, hs, hr⟩ := ih
    exact ⟨c :: s, .lit (by simp [csEq]) hs, .cons hc hr⟩
  | @qm x _ _ _ ih =>
    obtain ⟨s, hs, hr⟩ := ih
    exact ⟨x :: s, .qm hs, .cons (ciEq_refl x) hr⟩
  | starNil _ ih =>
    obtain ⟨s, hs, hr⟩ := ih
    exact ⟨s, .starNil hs, hr⟩
  | @starCons x _ _ _ ih =>
    obtain ⟨s, hs, hr⟩ := ih
    exact ⟨x :: s, .starCons hs, .cons (ciEq_refl x) hr⟩

theorem tokM_ci_of_spelling {ts s y} (h : TokM csEq ts s) (hr : CiRel s y) : TokM ciEq ts y := by
  induction h generalizing y with
  | nil => cases hr; exact .nil
  | lit hc _ ih =>
    cases hr with
    | cons hxy hr =>
      simp [csEq] at hc; subst hc
      exact .lit hxy (ih hr)
  | qm _ ih => cases hr with | cons _ hr => exact .qm (ih hr)
  | starNil _ ih => exact .starNil (ih hr)
  | starCons _ ih => cases hr with | cons _ hr => exact .starCons (ih hr)

abbrev CiSegs (ss ys : List Str) : Prop := Forall2 CiRel ss ys

theorem segsM_ci_spelling {ps ys} (h : SegsM ciEq ps ys) : ∃ ss, SegsM csEq ps ss ∧ CiSegs ss ys := by
  induction h with
  | nil => exact ⟨[], .nil, .nil⟩
  | one ht _ ih =>
    obtain ⟨s, hs, hr⟩ := tokM_ci_spelling ht
    obtain ⟨ss, hss, hrr⟩ := ih
    exact ⟨s :: ss, .one hs hss, .cons hr hrr⟩
  | @anyLast ys hne =>
    refine ⟨ys, .anyLast hne, ?_⟩
    exact Forall2.refl (fun s => Forall2.refl ciEq_refl s) ys
  | anySkip hp _ ih =>
    obtain ⟨ss, hss, hr⟩ := ih
    exact ⟨ss, .anySkip hp hss, hr⟩
  | @anyEat _ y _ hp _ ih =>
    obtain ⟨ss, hss, hr⟩ := ih
    exact ⟨y :: ss, .anyEat hp hss,
      .cons (Forall2.refl ciEq_refl y) hr⟩

theorem CiSegs.ne_nil {ss ys} (h : CiSegs ss ys) (hy : ys ≠ []) : ss ≠ [] := by
  cases h with
  | nil => exact hy
  | cons _ _ => simp

theorem segsM_ci_of_spelling {ps ss ys} (h : SegsM csEq ps ss) (hr : CiSegs ss ys) : SegsM ciEq ps ys := by
  induction h generalizing ys with
  | nil => cases hr; exact .nil
  | one ht _ ih => cases hr with | cons h1 h2 => exact .one (tokM_ci_of_spelling ht h1) (ih h2)
  | anyLast hne =>
    refine .anyLast ?_
    cases hr with
    | nil => exact absurd rfl hne
    | cons _ _ => simp
  | anySkip hp _ ih => exact .anySkip hp (ih hr)
  | anyEat hp _ ih => cases hr with | cons _ h2 => exact .anyEat hp (ih h2)

end Wicket
