import Wicket.Glob

/-!
# Host patterns (#322, item 2)

`wicket_core::manifest::host_matches`: a pattern is a host name, or `*.suffix` for one or more
labels under `suffix` (never `suffix` itself); both sides ignore ASCII case, and the host's trailing
dots are dropped. `subset::host_covers` decides whether every host one pattern matches is matched by
another; `hostCovers_sound` proves it.
-/

namespace Wicket

def lowerS (s : Str) : Str := s.map Char.toLower

/-- Drops trailing dots (`trim_end_matches('.')`). -/
def trimDots (s : Str) : Str := (s.reverse.dropWhile (· == '.')).reverse

/-- The suffix of a `*.suffix` pattern. -/
def stripWild : Str → Option Str
  | '*' :: '.' :: s => some s
  | _ => none

/-- A lowered pattern against a lowered, trimmed host. -/
def hm (p h : Str) : Bool :=
  match stripWild p with
  | some suf => decide (suf.length + 1 < h.length) && ('.' :: suf).isSuffixOf h
  | none => h == p

/-- `host_matches(pattern, host)`. (Rust compares byte lengths, this character lengths: either way
the host has a non-empty label in front of `.suffix`.) -/
def hostMatches (pat host : Str) : Bool := hm (lowerS pat) (lowerS (trimDots host))

/-- `subset::host_covers(parent, child)`. -/
def hostCovers (par ch : Str) : Bool :=
  let p := lowerS par
  let c := lowerS ch
  match stripWild c, stripWild p with
  | none, _ => hostMatches p c
  | some cs, some ps => cs == ps || ('.' :: ps).isSuffixOf cs
  | some _, none => false

/-! ## ASCII case -/

theorem toLower_toLower (c : Char) : c.toLower.toLower = c.toLower := by
  unfold Char.toLower
  split
  · rename_i h
    split
    · rename_i h2
      exfalso
      simp only at h h2
      have := h.1; have := h2.2
      simp_all [UInt32.le_iff_toNat_le, UInt32.toNat_add]
      omega
    · rfl
  · rfl

/-- Lowering never makes a character that isn't a lower-case letter. -/
theorem eq_of_toLower_eq {c d : Char} (hd : d.val < 'a'.val ∨ 'z'.val < d.val) (h : c.toLower = d) :
    c = d := by
  unfold Char.toLower at h
  split at h
  · rename_i hc
    exfalso
    subst h
    simp only at hc hd
    simp_all [UInt32.le_iff_toNat_le, UInt32.lt_iff_toNat_lt, UInt32.toNat_add]
    omega
  · exact h

theorem lowerS_lowerS (s : Str) : lowerS (lowerS s) = lowerS s := by
  simp [lowerS, toLower_toLower]

theorem dot_ne_lowered {x : Char} (h : x ≠ '.') : x.toLower ≠ '.' :=
  fun e => h (eq_of_toLower_eq (by decide) e)

/-! ## Trailing dots -/

theorem dropWhile_head {s : Str} : ∀ x, (s.dropWhile (· == '.')).head? = some x → x ≠ '.' := by
  induction s with
  | nil => simp
  | cons c s ih =>
    intro x hx
    simp only [List.dropWhile_cons] at hx
    split at hx
    · exact ih x hx
    · rename_i h; simp at hx; subst hx; simpa using h

theorem dropWhile_of_head {s : Str} (h : ∀ x, s.head? = some x → x ≠ '.') : s.dropWhile (· == '.') = s := by
  cases s with
  | nil => rfl
  | cons c s =>
    have : c ≠ '.' := h c rfl
    simp [this]

/-- A lowered, trimmed host is its own lowered, trimmed form. -/
theorem trim_lower_trim (h : Str) : lowerS (trimDots (lowerS (trimDots h))) = lowerS (trimDots h) := by
  have hhead : ∀ x, (lowerS (trimDots h)).reverse.head? = some x → x ≠ '.' := by
    intro x hx
    simp only [lowerS, trimDots, List.reverse_reverse, ← List.map_reverse, List.head?_map,
      Option.map_eq_some_iff] at hx
    obtain ⟨y, hy, rfl⟩ := hx
    exact dot_ne_lowered (dropWhile_head y hy)
  have : trimDots (lowerS (trimDots h)) = lowerS (trimDots h) := by
    show (((lowerS (trimDots h)).reverse.dropWhile (· == '.')).reverse) = _
    rw [dropWhile_of_head hhead, List.reverse_reverse]
  rw [this, lowerS_lowerS]

/-! ## Soundness of `host_covers` -/

theorem hostCovers_sound {par ch h : Str} (hc : hostCovers par ch = true) (hmc : hostMatches ch h = true) :
    hostMatches par h = true := by
  unfold hostCovers at hc
  unfold hostMatches at hmc ⊢
  generalize hC : lowerS ch = C at hc hmc
  generalize hP : lowerS par = P at hc ⊢
  generalize hH : lowerS (trimDots h) = H at hmc ⊢
  unfold hm at hmc
  simp only at hc
  cases hwc : stripWild C with
  | none =>
    rw [hwc] at hc hmc
    simp only [beq_iff_eq] at hmc
    subst hmc
    simp only at hc
    unfold hostMatches at hc
    have e1 : lowerS P = P := by rw [← hP, lowerS_lowerS]
    have e2 : lowerS (trimDots H) = H := by rw [← hH, trim_lower_trim]
    rw [e1, e2] at hc
    exact hc
  | some cs =>
    rw [hwc] at hc hmc
    cases hwp : stripWild P with
    | none => rw [hwp] at hc; simp at hc
    | some ps =>
      rw [hwp] at hc
      unfold hm
      rw [hwp]
      simp only [Bool.and_eq_true, decide_eq_true_eq, List.isSuffixOf_iff_suffix] at hmc ⊢
      simp only [Bool.or_eq_true, beq_iff_eq, List.isSuffixOf_iff_suffix] at hc
      rcases hc with rfl | hc
      · exact hmc
      · have h1 : ('.' :: ps) <:+ ('.' :: cs) := hc.trans (List.suffix_cons _ _)
        have h2 := h1.trans hmc.2
        have h3 := hc.length_le
        simp only [List.length_cons] at h3
        exact ⟨by omega, h2⟩

end Wicket
