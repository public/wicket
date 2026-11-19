import Wicket.Host

/-!
# What a widened node CA is signed for (#573)

A node CA is name-constrained to permitted DNS subtrees: `h` permits `h` and every name under it,
`.d` the names under `d` (not `d`), and `*` (the control host's own node) any name
(`splice::subtree_permits`). A renewal signs the operator's hosts and what live runs want beyond
them (`splice::widen`, called by `controlca::target`), without entries another covers
(`splice::merge_subtrees`, by `subtree_covers`).

- `covers_sound`: an entry that `subtree_covers` says covers another permits every name that one
  permits.
- `widen_keeps_base`: every name an operator's host permits, the widened CA permits: the operator's
  hosts are never dropped, capped or narrowed.
- `widen_keeps_wants`: every want kept is permitted too.
- `widen_from_inputs`: every entry of the widened CA is (lower-cased) an operator's host or a want,
  so `widen_no_star`: with no `*` among them, a remote node's CA never has one. (A want is recorded
  only as `ca_subtree` gives it, which never has a `*`: `splice.rs`'s tests, since `ca_subtree`'s
  IDNA parsing is outside the spec.)
- `widen_within_cap`: it has no more entries than the operator's hosts and the cap allow.
-/

namespace Wicket

def star : Str := ['*']

/-- `splice::subtree_permits(subtree, host)`. -/
def subtreePermits (st host : Str) : Bool :=
  if st = star then true
  else
    let h := lowerS (trimDots host)
    match lowerS st with
    | '.' :: b => decide (b.length + 1 < h.length) && ('.' :: b).isSuffixOf h
    | s => h == s || ('.' :: s).isSuffixOf h

/-- `splice::subtree_covers(p, need)`. -/
def subtreeCovers (p need : Str) : Bool :=
  if p = star then true
  else
    let q := lowerS p
    match lowerS need with
    | '.' :: d => q == d || q == '.' :: d || subtreePermits q d
    | n => q == n || subtreePermits q n

/-- `merge_subtrees`'s loop, with what it has kept so far. -/
def mergeAux (out : List Str) : List Str → List Str
  | [] => out
  | e0 :: rest =>
    if !(rest.any (fun o => !(lowerS o == lowerS e0) && subtreeCovers o (lowerS e0))) &&
        !(out.any (fun o => subtreeCovers o (lowerS e0))) then
      mergeAux ((out.filter (fun o => !subtreeCovers (lowerS e0) o)) ++ [lowerS e0]) rest
    else mergeAux out rest

/-- `splice::merge_subtrees(entries)`. -/
def mergeSubtrees (es : List Str) : List Str := mergeAux [] es

/-- Whether `permitted` covers `n` (`uncovered(permitted, [n])` is empty). -/
def coveredBy (permitted : List Str) (n : Str) : Bool := permitted.any (fun p => subtreeCovers p n)

/-- Each run once, in the order it first wants something. -/
def runsOf : List Str → List Str
  | [] => []
  | r :: l => r :: (runsOf l).filter (· != r)

/-- The order `widen` takes wants in: round `k` takes each run's `k`th, runs in order. -/
def roundRobin (ws : List (Str × Str)) : List Str :=
  let runs := runsOf (ws.map (·.1))
  let queue := fun r => (ws.filter (fun w => w.1 == r)).map (·.2)
  (List.range ws.length).flatMap (fun k => runs.filterMap (fun r => (queue r)[k]?))

/-- One want taken: skipped if covered, kept if there is room, else dropped (once). -/
def takeWant (base : List Str) (room : Nat) (st : List Str × List Str) (h : Str) : List Str × List Str :=
  if coveredBy (base ++ st.1) h then st
  else if st.1.length < room then (st.1 ++ [h], st.2)
  else if st.2.contains h then st
  else (st.1, st.2 ++ [h])

/-- The wants `widen` keeps and drops. -/
def widenKept (base : List Str) (ws : List (Str × Str)) (max : Nat) : List Str × List Str :=
  (roundRobin (ws.filter (fun w => !coveredBy base w.2))).foldl (takeWant base (max - base.length)) ([], [])

/-- `splice::widen(base, wants, max)`: the CA's entries, and the wants left out. -/
def widen (base : List Str) (ws : List (Str × Str)) (max : Nat) : List Str × List Str :=
  let k := widenKept base ws max
  (mergeSubtrees (base ++ k.1), k.2)

/-! ## Lower case and trailing dots -/

theorem lowerS_append (a b : Str) : lowerS (a ++ b) = lowerS a ++ lowerS b := by simp [lowerS]

theorem lowerS_length (a : Str) : (lowerS a).length = a.length := by simp [lowerS]

theorem lowerS_eq_star {s : Str} (h : lowerS s = star) : s = star := by
  have hl : s.length = 1 := by rw [← lowerS_length, h]; rfl
  match s, hl with
  | [c], _ =>
    simp only [lowerS, List.map_cons, List.map_nil, star, List.cons.injEq, and_true] at h
    rw [eq_of_toLower_eq (d := '*') (by decide) h]; rfl

/-- A trimmed, lowered host doesn't end with `.`. -/
theorem host_last_ne_dot (h : Str) : ∀ x, (lowerS (trimDots h)).getLast? = some x → x ≠ '.' := by
  intro x hx
  simp only [lowerS, trimDots, List.getLast?_map, List.getLast?_reverse, Option.map_eq_some_iff] at hx
  obtain ⟨y, hy, rfl⟩ := hx
  exact dot_ne_lowered (dropWhile_head y hy)

theorem trimDots_of_last {s : Str} (h : ∀ x, s.getLast? = some x → x ≠ '.') : trimDots s = s := by
  unfold trimDots
  rw [dropWhile_of_head (by simpa [List.head?_reverse] using h)]
  simp

/-- A string a trimmed host ends with, ending in `.` after some character, can't be. -/
theorem suffix_last_ne_dot {s H : Str} (hH : ∀ x, H.getLast? = some x → x ≠ '.') (hs : s <:+ H) :
    ∀ x, s.getLast? = some x → x ≠ '.' := by
  obtain ⟨t, rfl⟩ := hs
  intro x hx
  apply hH x
  rw [List.getLast?_append]
  simp [hx]

/-! ## Permitting, semantically -/

/-- What a lowered subtree (not `*`) permits of a trimmed, lowered host. -/
def Under (s H : Str) : Prop :=
  match s with
  | '.' :: b => b.length + 1 < H.length ∧ ('.' :: b) <:+ H
  | s => H = s ∨ ('.' :: s) <:+ H

theorem permits_iff {st host : Str} (hst : st ≠ star) :
    subtreePermits st host = true ↔ Under (lowerS st) (lowerS (trimDots host)) := by
  unfold subtreePermits Under
  simp only [hst, ↓reduceIte]
  split <;> simp [List.isSuffixOf_iff_suffix]

theorem lowerS_ne_star {s : Str} (h : s ≠ star) : lowerS s ≠ star := fun e => h (lowerS_eq_star e)

theorem permits_lower {st host : Str} : subtreePermits (lowerS st) host = subtreePermits st host := by
  by_cases h : st = star
  · subst h; rfl
  · apply Bool.eq_iff_iff.mpr
    rw [permits_iff (lowerS_ne_star h), permits_iff h, lowerS_lowerS]

/-- Under a subtree, for hosts already trimmed and lowered. -/
theorem permits_host {st H : Str} (hst : st ≠ star) (hH : ∀ x, H.getLast? = some x → x ≠ '.') (hl : lowerS H = H) :
    subtreePermits st H = true ↔ Under (lowerS st) H := by
  rw [permits_iff hst, trimDots_of_last hH, hl]

theorem lowerS_of_suffix {s H : Str} (hl : lowerS H = H) (hs : s <:+ H) : lowerS s = s := by
  obtain ⟨t, rfl⟩ := hs
  rw [lowerS_append] at hl
  exact (List.append_inj hl (lowerS_length t)).2

/-- If `x` is under subtree `s` and `H` is `x` or has `.x` at its end, `H` is under `s`. -/
theorem under_of_under {s x H : Str} (hx : Under s x) (hH : H = x ∨ ('.' :: x) <:+ H) : Under s H := by
  unfold Under at hx ⊢
  split at hx
  · rename_i b
    obtain ⟨hlen, hsuf⟩ := hx
    rcases hH with rfl | hH
    · exact ⟨hlen, hsuf⟩
    · refine ⟨?_, hsuf.trans (List.suffix_cons _ _ |>.trans hH)⟩
      have := hH.length_le
      simp at this; omega
  · rcases hx with rfl | hx <;> rcases hH with rfl | hH
    · exact .inl rfl
    · exact .inr hH
    · exact .inr hx
    · exact .inr (hx.trans (List.suffix_cons _ _ |>.trans hH))

/-- **`subtree_covers` is sound**: an entry that covers another permits every name it permits. -/
theorem covers_sound {p n h : Str} (hc : subtreeCovers p n = true) (hn : subtreePermits n h = true) :
    subtreePermits p h = true := by
  by_cases hp : p = star
  · subst hp; rfl
  by_cases hns : n = star
  · subst hns
    -- only `*` covers `*`
    exfalso
    have hlp := lowerS_ne_star hp
    have e : subtreeCovers p star = (lowerS p == star || subtreePermits (lowerS p) star) := by
      simp only [subtreeCovers, hp, ↓reduceIte]; rfl
    rw [e, Bool.or_eq_true, beq_iff_eq] at hc
    rcases hc with e | e
    · exact hlp e
    · rw [permits_iff hlp, lowerS_lowerS] at e
      have ht : lowerS (trimDots ['*']) = ['*'] := by decide
      rw [star, ht] at e
      revert e hlp
      generalize lowerS p = q
      intro hlp e
      unfold Under at e
      split at e
      · simp at e
      · rcases e with e | e
        · exact hlp e.symm
        · have := e.length_le; simp at this; subst this; revert e; decide
  have hH := host_last_ne_dot h
  have hHl : lowerS (lowerS (trimDots h)) = lowerS (trimDots h) := lowerS_lowerS _
  rw [permits_iff hns] at hn
  rw [permits_iff hp]
  generalize lowerS (trimDots h) = H at hH hHl hn ⊢
  unfold subtreeCovers at hc
  simp only [hp, ↓reduceIte] at hc
  have hq : lowerS (lowerS p) = lowerS p := lowerS_lowerS p
  have hqs : lowerS p ≠ star := lowerS_ne_star hp
  generalize lowerS p = q at hc hq hqs ⊢
  generalize hm : lowerS n = m at hc hn
  unfold Under at hn
  split at hc
  · -- n = .d
    rename_i d
    simp only [Bool.or_eq_true, beq_iff_eq] at hc
    obtain ⟨hlen, hsuf⟩ := hn
    -- H = c :: … ++ '.' :: d
    have hdl : ∀ x, d.getLast? = some x → x ≠ '.' := by
      have := suffix_last_ne_dot hH hsuf
      intro x hx; apply this x; simp [List.getLast?_cons, hx]
    rcases hc with (rfl | rfl) | hc
    · -- q = d
      unfold Under
      split
      · rename_i b
        exact ⟨by simp at hlen ⊢; omega, (List.suffix_cons _ _).trans hsuf⟩
      · exact .inr hsuf
    · exact ⟨hlen, hsuf⟩
    · have hd := (permits_host hqs hdl (lowerS_of_suffix hHl (List.suffix_cons _ _ |>.trans hsuf))).mp hc
      rw [hq] at hd
      exact under_of_under hd (.inr hsuf)
  · rename_i hnd
    have hn : H = m ∨ ('.' :: m) <:+ H := by
      split at hn
      · exact absurd rfl (hnd _)
      · exact hn
    simp only [Bool.or_eq_true, beq_iff_eq] at hc
    rcases hc with rfl | hc
    · unfold Under
      split
      · exact absurd rfl (hnd _)
      · exact hn
    · have hml : ∀ x, m.getLast? = some x → x ≠ '.' := by
        rcases hn with rfl | hn
        · exact hH
        · have := suffix_last_ne_dot hH hn
          intro x hx; apply this x; simp [List.getLast?_cons, hx]
      have hmlow : lowerS m = m := by
        rcases hn with rfl | hn
        · exact hHl
        · exact lowerS_of_suffix hHl (List.suffix_cons _ _ |>.trans hn)
      have hd := (permits_host hqs hml hmlow).mp hc
      rw [hq] at hd
      exact under_of_under hd hn

/-! ## Merging keeps every name -/

theorem mem_mergeAux {o : Str} : ∀ {out es : List Str}, o ∈ mergeAux out es → o ∈ out ∨ ∃ e ∈ es, o = lowerS e
  | out, [], h => .inl h
  | out, e0 :: rest, h => by
    unfold mergeAux at h
    split at h
    · rcases mem_mergeAux h with h | ⟨e, he, rfl⟩
      · simp only [List.mem_append, List.mem_filter, List.mem_singleton] at h
        rcases h with ⟨h, _⟩ | rfl
        · exact .inl h
        · exact .inr ⟨e0, List.mem_cons_self, rfl⟩
      · exact .inr ⟨e, List.mem_cons_of_mem _ he, rfl⟩
    · rcases mem_mergeAux h with h | ⟨e, he, rfl⟩
      · exact .inl h
      · exact .inr ⟨e, List.mem_cons_of_mem _ he, rfl⟩

/-- Every entry `merge_subtrees` keeps is one it was given, lower-cased. -/
theorem mem_merge {o : Str} {es : List Str} (h : o ∈ mergeSubtrees es) : ∃ e ∈ es, o = lowerS e := by
  rcases mem_mergeAux h with h | h
  · simp at h
  · exact h

theorem merge_permits_aux {h : Str} : ∀ {out es : List Str}, (∃ x ∈ out ++ es, subtreePermits x h = true) →
    ∃ o ∈ mergeAux out es, subtreePermits o h = true
  | out, [], hx => by simpa [mergeAux] using hx
  | out, e0 :: rest, ⟨x, hx, hxh⟩ => by
    unfold mergeAux
    have he : subtreePermits (lowerS e0) h = subtreePermits e0 h := permits_lower
    split
    · rename_i hcond
      apply merge_permits_aux
      simp only [List.mem_append, List.mem_cons] at hx
      rcases hx with hx | rfl | hx
      · by_cases hc : subtreeCovers (lowerS e0) x = true
        · exact ⟨lowerS e0, by simp, covers_sound hc hxh⟩
        · exact ⟨x, by simp [hx, hc], hxh⟩
      · exact ⟨lowerS x, by simp, by rw [he]; exact hxh⟩
      · exact ⟨x, by simp [hx], hxh⟩
    · rename_i hcond
      apply merge_permits_aux
      simp only [List.mem_append, List.mem_cons] at hx
      rcases hx with hx | rfl | hx
      · exact ⟨x, by simp [hx], hxh⟩
      · have hxe : subtreePermits (lowerS x) h = true := by rw [permits_lower]; exact hxh
        by_cases hl : (rest.any fun o => !(lowerS o == lowerS x) && subtreeCovers o (lowerS x)) = true
        · obtain ⟨o, ho, hoc⟩ := List.any_eq_true.mp hl
          simp only [Bool.and_eq_true] at hoc
          exact ⟨o, by simp [ho], covers_sound hoc.2 hxe⟩
        · have hr : (out.any fun o => subtreeCovers o (lowerS x)) = true := by
            simp only [Bool.not_eq_true] at hl
            simpa [hl] using hcond
          obtain ⟨o, ho, hoc⟩ := List.any_eq_true.mp hr
          exact ⟨o, by simp [ho], covers_sound hoc hxe⟩
      · exact ⟨x, by simp [hx], hxh⟩

/-- **Merging drops no name**: every name an entry permits, an entry `merge_subtrees` keeps permits. -/
theorem merge_permits {es : List Str} {e h : Str} (he : e ∈ es) (hp : subtreePermits e h = true) :
    ∃ o ∈ mergeSubtrees es, subtreePermits o h = true :=
  merge_permits_aux ⟨e, by simpa using he, hp⟩

theorem length_mergeAux : ∀ {out es : List Str}, (mergeAux out es).length ≤ out.length + es.length
  | out, [] => by simp [mergeAux]
  | out, e0 :: rest => by
    unfold mergeAux
    split
    · have := length_mergeAux (out := (out.filter (fun o => !subtreeCovers (lowerS e0) o)) ++ [lowerS e0]) (es := rest)
      have hf := List.length_filter_le (fun o => !subtreeCovers (lowerS e0) o) out
      simp only [List.length_append, List.length_cons, List.length_nil] at this ⊢
      omega
    · have := length_mergeAux (out := out) (es := rest)
      simp only [List.length_cons]; omega

/-! ## The widened CA -/

theorem mem_roundRobin {ws : List (Str × Str)} {h : Str} (hm : h ∈ roundRobin ws) : ∃ w ∈ ws, w.2 = h := by
  simp only [roundRobin, List.mem_flatMap, List.mem_filterMap] at hm
  obtain ⟨_, _, r, _, hr⟩ := hm
  have := List.mem_of_getElem? hr
  simp only [List.mem_map, List.mem_filter] at this
  obtain ⟨w, ⟨hw, _⟩, rfl⟩ := this
  exact ⟨w, hw, rfl⟩

theorem takeWant_kept {base : List Str} {room : Nat} :
    ∀ {l : List Str} {st : List Str × List Str} {x : Str}, x ∈ (l.foldl (takeWant base room) st).1 → x ∈ st.1 ∨ x ∈ l
  | [], st, x, h => .inl h
  | a :: l, st, x, h => by
    simp only [List.foldl_cons] at h
    rcases takeWant_kept h with h | h
    · unfold takeWant at h
      split at h
      · exact .inl h
      · split at h
        · simp only [List.mem_append, List.mem_singleton] at h
          rcases h with h | rfl
          · exact .inl h
          · exact .inr List.mem_cons_self
        · split at h <;> exact .inl h
    · exact .inr (List.mem_cons_of_mem _ h)

theorem takeWant_room {base : List Str} {room : Nat} :
    ∀ {l : List Str} {st : List Str × List Str}, st.1.length ≤ room → (l.foldl (takeWant base room) st).1.length ≤ room
  | [], st, h => h
  | a :: l, st, h => by
    simp only [List.foldl_cons]
    apply takeWant_room
    unfold takeWant
    split
    · exact h
    · split
      · rename_i hl; simp only [List.length_append, List.length_singleton]; omega
      · split <;> exact h

/-- What `widen` keeps is wanted. -/
theorem mem_widenKept {base : List Str} {ws : List (Str × Str)} {max : Nat} {x : Str}
    (h : x ∈ (widenKept base ws max).1) : ∃ w ∈ ws, w.2 = x := by
  rcases takeWant_kept h with h | h
  · simp at h
  · obtain ⟨w, hw, rfl⟩ := mem_roundRobin h
    exact ⟨w, (List.mem_filter.mp hw).1, rfl⟩

/-- **The operator's hosts are always signed** (#573): every name one of them permits, the widened
CA permits. No want, cap or merge takes one out. -/
theorem widen_keeps_base {base : List Str} {ws : List (Str × Str)} {max : Nat} {b h : Str}
    (hb : b ∈ base) (hp : subtreePermits b h = true) :
    ∃ o ∈ (widen base ws max).1, subtreePermits o h = true :=
  merge_permits (List.mem_append_left _ hb) hp

/-- And every want kept is permitted, as wanted. -/
theorem widen_keeps_wants {base : List Str} {ws : List (Str × Str)} {max : Nat} {k h : Str}
    (hk : k ∈ (widenKept base ws max).1) (hp : subtreePermits k h = true) :
    ∃ o ∈ (widen base ws max).1, subtreePermits o h = true :=
  merge_permits (List.mem_append_right _ hk) hp

/-- **Nothing new is signed**: every entry of the widened CA is an operator's host or a want,
lower-cased. -/
theorem widen_from_inputs {base : List Str} {ws : List (Str × Str)} {max : Nat} {o : Str}
    (h : o ∈ (widen base ws max).1) : ∃ e, (e ∈ base ∨ ∃ w ∈ ws, w.2 = e) ∧ o = lowerS e := by
  obtain ⟨e, he, rfl⟩ := mem_merge h
  rcases List.mem_append.mp he with he | he
  · exact ⟨e, .inl he, rfl⟩
  · exact ⟨e, .inr (mem_widenKept he), rfl⟩

/-- **A remote node's CA never permits every name**: with no `*` among the operator's hosts and the
wants (`ca_subtree` never gives one), the widened CA has none. -/
theorem widen_no_star {base : List Str} {ws : List (Str × Str)} {max : Nat}
    (hb : star ∉ base) (hw : ∀ w ∈ ws, w.2 ≠ star) : star ∉ (widen base ws max).1 := by
  intro h
  obtain ⟨e, he, hs⟩ := widen_from_inputs h
  have := lowerS_eq_star hs.symm
  subst this
  rcases he with he | ⟨w, hw', hws⟩
  · exact hb he
  · exact hw w hw' hws

/-- **Within the cap**: no more entries than the operator's hosts, or the cap. -/
theorem widen_within_cap {base : List Str} {ws : List (Str × Str)} {max : Nat} :
    (widen base ws max).1.length ≤ base.length + (max - base.length) := by
  have hk : (widenKept base ws max).1.length ≤ max - base.length := takeWant_room (by simp)
  have := length_mergeAux (out := []) (es := base ++ (widenKept base ws max).1)
  simp only [widen, mergeSubtrees, List.length_append, List.length_nil] at this ⊢
  omega

end Wicket
