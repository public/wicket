import Wicket.Subset

/-!
# Canonical paths: a normalized path can't escape a rule (#322, item 2)

`wicket_core::canon::canonical_path` decides a request on its path only if that path has one
spelling: no dot or empty segments, no `;`, no backslash or control character, nothing a URL parser
would percent-encode on the way upstream (space, `"`, `#`, `<`, `>`, `?`, `` ` ``, `{`, `}` or a
non-ASCII byte: those go percent-encoded), and every `%` an
upper-case escape of a byte that has to be escaped (never `/`, `\`, `.`, NUL, `%` or an unreserved
character). Nothing is decoded, unless a zone's reach rule for the host names segments in which one
encoded slash is decided as `/` (`decode_slash`, #664): `canonical_path_decoding`, whose result
passes the same checks (`canonicalPathDecoding_plain`).

An upstream may read a path differently: it may percent-decode it, and resolve dot segments
(RFC 3986 §5.2.4), in either order. On a canonical path neither changes which segments it names
(`upstream_eq`), so:
- a rule `Q/**` that matches a canonical path still holds it under `Q/` as the upstream reads it
  (`reach_no_escape`);
- a path the upstream reads as under `Q/` (for `Q` spelled in unreserved characters) is matched by
  wicket's rule `Q/**` too (`forbid_no_escape`): no encoding or dot segment dodges a forbid.
-/

namespace Wicket

/-! ## The check -/

def isHex (c : Char) : Bool := (48 ≤ c.toNat && c.toNat ≤ 57) || (65 ≤ c.toNat && c.toNat ≤ 70)

def hexVal (c : Char) : Nat := if c.toNat ≤ 57 then c.toNat - 48 else c.toNat - 55

/-- RFC 3986's unreserved bytes: letters, digits, `-`, `.`, `_`, `~`. -/
def unreservedNat (v : Nat) : Bool :=
  (48 ≤ v && v ≤ 57) || (65 ≤ v && v ≤ 90) || (97 ≤ v && v ≤ 122) || v == 45 || v == 46 || v == 95 || v == 126

def unreservedChar (c : Char) : Bool := unreservedNat c.toNat

/-- A byte an escape may stand for: not `/`, `\`, NUL or `%`, and not unreserved (`.` included). -/
def escByteOk (v : Nat) : Bool := !(v == 47 || v == 92 || v == 0 || v == 37) && !unreservedNat v

/-- `check_escapes`. -/
def escapesOk : Str → Bool
  | [] => true
  | '%' :: a :: b :: rest => isHex a && isHex b && escByteOk (16 * hexVal a + hexVal b) && escapesOk rest
  | '%' :: _ => false
  | _ :: rest => escapesOk rest

def badChar (c : Char) : Bool := c == '\\' || c.toNat < 0x20 || c.toNat == 0x7f

/-- What a URL parser would percent-encode on the way upstream (WHATWG's path percent-encode set,
and every non-ASCII character: a byte of 0x80 or more, as the symbols are UTF-8 bytes), so
`check_plain` refuses it unescaped: the decided path is then the one sent. -/
def unescapedChar (c : Char) : Bool :=
  c ∈ [' ', '"', '#', '<', '>', '?', '`', '{', '}'] || 0x80 ≤ c.toNat

def stripSlash (b : Str) : Str := if b.getLast? = some '/' then b.dropLast else b

/-- The segment checks of `check_plain`. -/
def segsOk : Str → Bool
  | '/' :: body =>
    body.head? != some '/' &&
      (let b := stripSlash body
       b.isEmpty || (split b).all (fun s => s != [] && s != ['.'] && s != ['.', '.']))
  | _ => false

/-- `check_plain`. -/
def plainOk (p : Str) : Bool :=
  !p.any badChar && !p.any unescapedChar && !p.contains ';' && escapesOk p && segsOk p

/-- Where a segment's encoded slashes (`%2F`, `%2f`) start, scanning as `slash_escape` does. -/
def slashEscs : Str → Nat → List Nat
  | [], _ => []
  | c :: t, i =>
    match c, t with
    | '%', '2' :: d :: rest => if d == 'f' || d == 'F' then i :: slashEscs rest (i + 3) else slashEscs t (i + 1)
    | _, _ => slashEscs t (i + 1)

/-- `slash_escape`: the segment's only encoded slash, if it has one, between two non-empty parts. -/
def slashEscape (seg : Str) : Option Nat :=
  match slashEscs seg 0 with
  | [pos] => if decide (0 < pos) && decide (pos + 3 < seg.length) then some pos else none
  | _ => none

/-- A segment with its only encoded slash decoded, if it has one. -/
def decodeSeg (seg : Str) : Option Str :=
  (slashEscape seg).map (fun pos => seg.take pos ++ '/' :: seg.drop (pos + 3))

/-- The segments from number `k` on, those named in `segs` decoded; and whether any was. -/
def decodeParts : List Str → Nat → List Nat → List Str × Bool
  | [], _, _ => ([], false)
  | s :: rest, k, segs =>
    let r := decodeParts rest (k + 1) segs
    match (if segs.contains k then decodeSeg s else none) with
    | some d => (d :: r.1, true)
    | none => (s :: r.1, r.2)

/-- `decode_slash`: the path (starting with `/`) with the named segments decoded, if any was. -/
def decodeSlash (p : Str) (segs : List Nat) : Option Str :=
  if segs.isEmpty then none
  else
    let r := decodeParts (split p.tail) 1 segs
    if r.2 then some ('/' :: List.intercalate ['/'] r.1) else none

/-- `canonical_path_decoding(path_and_query, segs)`: the path decided on, or `none` (an error).
The symbols are bytes, as Rust checks them (the oracle passes UTF-8 bytes; `MAX_PATH` is in
bytes). -/
def canonicalPathDecoding (pq : Str) (segs : List Nat) : Option Str :=
  let path := pq.takeWhile (· != '?')
  if path.length > 4096 then none
  else if path.head? != some '/' then none
  else
    let p := (decodeSlash path segs).getD path
    if plainOk p then some p else none

/-- `canonical_path`: nothing decoded. -/
def canonicalPath (pq : Str) : Option Str := canonicalPathDecoding pq []

theorem canonicalPathDecoding_plain {pq p : Str} {segs : List Nat} (h : canonicalPathDecoding pq segs = some p) :
    plainOk p = true := by
  unfold canonicalPathDecoding at h
  simp only at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h; assumption
      · cases h

theorem canonicalPath_plain {pq p : Str} (h : canonicalPath pq = some p) : plainOk p = true :=
  canonicalPathDecoding_plain h

/-! ## How an upstream may read it -/

/-- Percent-decoding (bytes as characters). -/
def decode : Str → Str
  | '%' :: a :: b :: rest =>
    if isHex a && isHex b then Char.ofNat (16 * hexVal a + hexVal b) :: decode rest
    else '%' :: decode (a :: b :: rest)
  | c :: rest => c :: decode rest
  | [] => []

/-- Dot-segment resolution (RFC 3986 §5.2.4, on segments): `.` is dropped, `..` drops the one
before it. -/
def resolveAux : List Str → List Str → List Str
  | acc, [] => acc.reverse
  | acc, s :: ss =>
    if s = ['.'] then resolveAux acc ss
    else if s = ['.', '.'] then resolveAux acc.tail ss
    else resolveAux (s :: acc) ss

def resolve (ss : List Str) : List Str := resolveAux [] ss

/-! ## Lemmas -/

theorem toNat_ofNat_lt (v : Nat) (h : v < 256) : (Char.ofNat v).toNat = v := by
  have hv : v.isValidChar := Or.inl (by omega)
  rw [Char.ofNat, dite_eq_left_of_eq_true (eq_true hv)]
  rfl

theorem hexVal_lt {c : Char} (h : isHex c = true) : hexVal c < 16 := by
  simp only [isHex, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h
  unfold hexVal
  split <;> omega

theorem isHex_ne {c : Char} (h : isHex c = true) : c ≠ '/' ∧ c ≠ '%' := by
  constructor <;> (intro e; subst e; revert h; decide)

/-- The character an escape decodes to, and what it is not. -/
theorem escChar {a b : Char} (ha : isHex a = true) (hb : isHex b = true)
    (hok : escByteOk (16 * hexVal a + hexVal b) = true) :
    Char.ofNat (16 * hexVal a + hexVal b) ≠ '/' ∧ unreservedChar (Char.ofNat (16 * hexVal a + hexVal b)) = false := by
  have h1 := hexVal_lt ha
  have h2 := hexVal_lt hb
  have hv : 16 * hexVal a + hexVal b < 256 := by omega
  have ht := toNat_ofNat_lt _ hv
  generalize 16 * hexVal a + hexVal b = v at ht hok hv
  simp only [escByteOk, Bool.and_eq_true, Bool.not_eq_true', Bool.or_eq_false_iff, beq_eq_false_iff_ne] at hok
  constructor
  · intro e
    rw [e] at ht
    have : ('/' : Char).toNat = 47 := rfl
    omega
  · simp only [unreservedChar, ht]; exact hok.2

theorem decode_cons {c : Char} (hc : c ≠ '%') (r : Str) : decode (c :: r) = c :: decode r := by
  rw [decode.eq_def]; split <;> simp_all

theorem escapesOk_cons {c : Char} (hc : c ≠ '%') (r : Str) : escapesOk (c :: r) = escapesOk r := by
  rw [escapesOk.eq_def]; split <;> simp_all

/-- Decoding commutes with splitting at `/`, and every segment's escapes are valid. -/
theorem decode_splitAux (p : Str) (h : escapesOk p = true) :
    (splitAux (decode p)).1 = decode (splitAux p).1 ∧ (splitAux (decode p)).2 = (splitAux p).2.map decode ∧
      escapesOk (splitAux p).1 = true ∧ ∀ s ∈ (splitAux p).2, escapesOk s = true := by
  induction p using decode.induct with
  | case1 a b rest hab ih =>
    simp only [escapesOk, Bool.and_eq_true] at h
    obtain ⟨⟨⟨ha, hb⟩, hok⟩, hr⟩ := h
    obtain ⟨i1, i2, i3, i4⟩ := ih hr
    have ⟨hx, _⟩ := escChar ha hb hok
    have ⟨ha1, _⟩ := isHex_ne ha
    have ⟨hb1, _⟩ := isHex_ne hb
    simp only [decode, ha, hb, Bool.and_self, ite_true, splitAux, hx, ha1, hb1, ite_false,
      show ('%' : Char) ≠ '/' by decide]
    refine ⟨by rw [i1], i2, ?_, i4⟩
    simp [escapesOk, ha, hb, hok, i3]
  | case2 a b rest hab ih =>
    simp only [escapesOk, Bool.and_eq_true] at h
    simp_all
  | case3 c rest hc ih =>
    have hpc : c ≠ '%' := by
      rintro rfl
      match rest, hc, h with
      | [], _, h => simp [escapesOk] at h
      | [_], _, h => simp [escapesOk] at h
      | a :: b :: r, hc, _ => exact absurd rfl (hc a b r rfl)
    rw [escapesOk_cons hpc] at h
    obtain ⟨i1, i2, i3, i4⟩ := ih h
    rw [decode_cons hpc]
    by_cases hs : c = '/'
    · subst hs
      simp only [splitAux, ite_true, List.map_cons]
      exact ⟨rfl, by rw [i1, i2], rfl, fun s hs => by
        rcases List.mem_cons.mp hs with rfl | hs
        · exact i3
        · exact i4 s hs⟩
    · simp only [splitAux, hs, ite_false]
      exact ⟨by rw [i1, decode_cons hpc], i2, by rw [escapesOk_cons hpc]; exact i3, i4⟩
  | case4 => simp [decode, splitAux, escapesOk]

theorem split_decode {p : Str} (h : escapesOk p = true) :
    split (decode p) = (split p).map decode ∧ ∀ s ∈ split p, escapesOk s = true := by
  obtain ⟨i1, i2, i3, i4⟩ := decode_splitAux p h
  refine ⟨by simp [split, i1, i2], fun s hs => ?_⟩
  rcases List.mem_cons.mp hs with rfl | hs
  · exact i3
  · exact i4 s hs

/-- Without `%`, decoding changes nothing. -/
theorem decode_of_no_pct {s : Str} (h : '%' ∉ s) : decode s = s := by
  induction s with
  | nil => rfl
  | cons c s ih =>
    have hc : c ≠ '%' := fun e => h (e ▸ List.mem_cons_self)
    rw [decode_cons hc, ih (fun e => h (List.mem_cons_of_mem _ e))]

theorem not_pct_of_escapesOk {c : Char} {rest : Str} (h : escapesOk (c :: rest) = true)
    (hc : ∀ a b r, c = '%' → ¬rest = a :: b :: r) : c ≠ '%' := by
  rintro rfl
  match rest, hc, h with
  | [], _, h => simp [escapesOk] at h
  | [_], _, h => simp [escapesOk] at h
  | a :: b :: r, hc, _ => exact absurd rfl (hc a b r rfl)

/-- **Encodings.** A segment whose decoded form is spelled in unreserved characters is spelled
that way already: no escape stands for an unreserved character (`/pro%64` is refused, not `/prod`). -/
theorem decode_eq_unreserved {s w : Str} (hs : escapesOk s = true) (hw : ∀ c ∈ w, unreservedChar c = true)
    (h : decode s = w) : s = w := by
  induction s using decode.induct generalizing w with
  | case1 a b rest hab _ =>
    simp only [escapesOk, Bool.and_eq_true] at hs
    obtain ⟨⟨⟨ha, hb⟩, hok⟩, _⟩ := hs
    simp only [decode, ha, hb, Bool.and_self, ite_true] at h
    subst h
    have := hw _ List.mem_cons_self
    rw [(escChar ha hb hok).2] at this
    cases this
  | case2 a b rest hab _ =>
    simp only [escapesOk, Bool.and_eq_true] at hs
    simp_all
  | case3 c rest hc ih =>
    have hpc := not_pct_of_escapesOk hs hc
    rw [escapesOk_cons hpc] at hs
    rw [decode_cons hpc] at h
    subst h
    exact congrArg _ (ih hs (fun x hx => hw x (List.mem_cons_of_mem _ hx)) rfl)
  | case4 => exact h

theorem segsOk_no_dots {p : Str} (h : segsOk p = true) :
    ∀ s ∈ split p, s ≠ ['.'] ∧ s ≠ ['.', '.'] := by
  unfold segsOk at h
  split at h
  case h_2 => cases h
  case h_1 body =>
    simp only [ Bool.and_eq_true, Bool.or_eq_true, List.isEmpty_iff, List.all_eq_true,
      bne_iff_ne, ne_eq] at h
    obtain ⟨_, hb⟩ := h
    rw [split_cons_slash]
    intro s hs
    rcases List.mem_cons.mp hs with rfl | hs
    · simp
    have hsplit : split body = split (stripSlash body) ∨ split body = split (stripSlash body) ++ [[]] := by
      unfold stripSlash
      split
      · rename_i hl
        right
        obtain ⟨ys, rfl⟩ := List.getLast?_eq_some_iff.mp hl
        rw [List.dropLast_concat, split_append_slash]
        rfl
      · left; rfl
    have hseg : ∀ x ∈ split (stripSlash body), x ≠ ['.'] ∧ x ≠ ['.', '.'] := by
      rcases hb with he | hb
      · rw [he]; intro x hx; simp [split, splitAux] at hx; subst hx; simp
      · intro x hx; have := hb x hx; exact ⟨this.1.2, this.2⟩
    rcases hsplit with e | e <;> rw [e] at hs
    · exact hseg s hs
    · rcases List.mem_append.mp hs with hs | hs
      · exact hseg s hs
      · simp at hs; subst hs; simp

theorem resolveAux_id (acc ss : List Str) (h : ∀ s ∈ ss, s ≠ ['.'] ∧ s ≠ ['.', '.']) :
    resolveAux acc ss = acc.reverse ++ ss := by
  induction ss generalizing acc with
  | nil => simp [resolveAux]
  | cons s ss ih =>
    have hs := h s List.mem_cons_self
    simp only [resolveAux, hs.1, hs.2, ite_false]
    rw [ih _ (fun x hx => h x (List.mem_cons_of_mem _ hx))]
    simp

/-- A path with no dot segments resolves to itself. -/
theorem resolve_id {ss : List Str} (h : ∀ s ∈ ss, s ≠ ['.'] ∧ s ≠ ['.', '.']) : resolve ss = ss := by
  simp [resolve, resolveAux_id [] ss h]

/-- **How an upstream reads a canonical path.** Decoding then resolving dot segments, or resolving
then decoding, it names the same segments: the canonical ones, each decoded. -/
theorem upstream_eq {p : Str} (h : plainOk p = true) :
    resolve (split (decode p)) = (split p).map decode ∧ (resolve (split p)).map decode = (split p).map decode := by
  simp only [plainOk, Bool.and_eq_true] at h
  obtain ⟨⟨_, hesc⟩, hsegs⟩ := h
  obtain ⟨hsd, hse⟩ := split_decode hesc
  have nodots := segsOk_no_dots hsegs
  refine ⟨?_, by rw [resolve_id nodots]⟩
  rw [hsd]
  apply resolve_id
  intro d hd
  obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hd
  have unres : ∀ w : Str, w = ['.'] ∨ w = ['.', '.'] → ∀ c ∈ w, unreservedChar c = true := by
    rintro w (rfl | rfl) c hc <;> simp at hc <;> subst hc <;> decide
  constructor
  · intro e
    exact (nodots s hs).1 (decode_eq_unreserved (hse s hs) (unres _ (Or.inl rfl)) e)
  · intro e
    exact (nodots s hs).2 (decode_eq_unreserved (hse s hs) (unres _ (Or.inr rfl)) e)

/-- **A normalized path can't escape a rule** (reach): a canonical path a rule `Q/**` matches is,
as the upstream reads it, under `Q/` still. -/
theorem reach_no_escape {p q : Str} (hp : plainOk p = true) (hq : q.all plainChar) (hpct : '%' ∉ q)
    (hm : Lang csEq (q ++ globstarSuffix) p) : ∃ t, t ≠ [] ∧ resolve (split (decode p)) = split q ++ t := by
  unfold Lang at hm
  rw [globParse_of_head (by rw [globstarSuffix, head_split_append]; exact head_plain hq), parse_globstar] at hm
  obtain ⟨t, ht, hrest⟩ := (segsM_plain_append (plain_of_split hq) _ _).mp hm
  have hne : t ≠ [] := hrest.ne_nil (by simp)
  refine ⟨t.map decode, by simpa using hne, ?_⟩
  rw [(upstream_eq hp).1, ht, List.map_append]
  congr 1
  have : ∀ s ∈ split q, decode s = s := fun s hs =>
    decode_of_no_pct (fun e => hpct (mem_of_mem_split hs e))
  clear ht hm hrest
  generalize split q = qs at this ⊢
  induction qs with
  | nil => rfl
  | cons s ss ih =>
    simp only [List.map_cons, this s List.mem_cons_self]
    rw [ih (fun x hx => this x (List.mem_cons_of_mem _ hx))]

theorem unreserved_plain {c : Char} (h : unreservedChar c = true) : plainChar c = true := by
  simp only [plainChar, Bool.and_eq_true, decide_eq_true_eq]
  constructor <;> (rintro rfl; revert h; decide)

/-- **A normalized path can't escape a rule** (forbid): a canonical path the upstream reads as
under `Q/`, for a `Q` spelled in unreserved characters and `/`, is matched by the rule `Q/**`
itself. Neither an escape nor a dot segment takes it out from under the rule. -/
theorem forbid_no_escape {p q : Str} (hp : plainOk p = true) (hq : ∀ c ∈ q, c = '/' ∨ unreservedChar c = true)
    (hup : ∃ t, t ≠ [] ∧ resolve (split (decode p)) = split q ++ t) : Lang csEq (q ++ globstarSuffix) p := by
  obtain ⟨t, hne, he⟩ := hup
  have hesc : escapesOk p = true := by
    simp only [plainOk, Bool.and_eq_true] at hp; exact hp.1.2
  have hse := (split_decode hesc).2
  rw [(upstream_eq hp).1] at he
  obtain ⟨A, B, hAB, hA, hB⟩ := List.map_eq_append_iff.mp he
  have hqs : ∀ s ∈ split q, ∀ c ∈ s, unreservedChar c = true := by
    intro s hs c hc
    rcases hq c (mem_of_mem_split hs hc) with rfl | h
    · exact absurd hc (slash_not_mem_split hs)
    · exact h
  have hAq : A = split q := by
    have hAe : ∀ a ∈ A, escapesOk a = true := fun a ha => hse a (hAB ▸ List.mem_append_left _ ha)
    have key : ∀ (A qs : List Str), (∀ a ∈ A, escapesOk a = true) → (∀ s ∈ qs, ∀ c ∈ s, unreservedChar c = true) →
        A.map decode = qs → A = qs := by
      intro A
      induction A with
      | nil => intro qs _ _ h; exact h
      | cons a A ih =>
        intro qs hA hq h
        cases qs with
        | nil => simp at h
        | cons q qs =>
          simp only [List.map_cons, List.cons.injEq] at h
          rw [decode_eq_unreserved (hA a List.mem_cons_self) (hq q List.mem_cons_self) h.1,
            ih qs (fun x hx => hA x (List.mem_cons_of_mem _ hx)) (fun s hs => hq s (List.mem_cons_of_mem _ hs)) h.2]
    exact key A (split q) hAe hqs hA
  have hqall : q.all plainChar := by
    simp only [List.all_eq_true]
    intro c hc
    rcases hq c hc with rfl | h
    · decide
    · exact unreserved_plain h
  unfold Lang
  rw [globParse_of_head (by rw [globstarSuffix, head_split_append]; exact head_plain hqall), parse_globstar, hAB, hAq]
  have hplain : ∀ s ∈ split q, s.all plainChar := by
    intro s hs
    simp only [List.all_eq_true]
    intro c hc
    exact unreserved_plain (hqs s hs c hc)
  refine (segsM_plain_append hplain _ _).mpr ⟨B, rfl, .anyLast ?_⟩
  intro hb
  apply hne
  rw [← hB, hb]
  rfl

/-- `prefix_dir(prefix)`: a grant's path prefix, ending in `/` so it covers whole segments (#119). -/
def prefixDir (p : Str) : Str :=
  if p.getLast? = some '/' then p else p ++ ['/']

/-- `prefix_covers(prefix, path)`: what a path-prefix grant covers, on the control host's ledger and
(#257 4a) on a node: the directory itself, or any path under it. -/
def prefixCovers (pre path : Str) : Bool :=
  (prefixDir pre).isPrefixOf path || (path ++ ['/']) == prefixDir pre

/-- The directory a prefix grant names: its prefix without a trailing `/` (`prefix_covers`'s
`dir`). -/
def prefixBase (p : Str) : Str := (prefixDir p).dropLast

theorem eq_dropLast_append : ∀ (p : Str) (c : Char), p.getLast? = some c → p = p.dropLast ++ [c]
  | [], _, h => by simp at h
  | [a], c, h => by simp at h; simp [h]
  | a :: b :: l, c, h => by
    have := eq_dropLast_append (b :: l) c (by simpa using h)
    simp only [List.dropLast_cons_cons, List.cons_append]
    exact congrArg (a :: ·) this

theorem prefixDir_eq (p : Str) : prefixDir p = prefixBase p ++ ['/'] := by
  unfold prefixBase prefixDir
  split
  · rename_i h; exact eq_dropLast_append p '/' h
  · simp

/-- **What a prefix grant covers** (#568): its directory itself, or a path that continues it with
`/`. Never a sibling that only starts with the same characters (`/a/app` covers neither
`/a/app-secrets` nor `/a/ap`). -/
theorem prefixCovers_iff {pre path : Str} :
    prefixCovers pre path = true ↔ path = prefixBase pre ∨ ∃ w, path = prefixBase pre ++ '/' :: w := by
  unfold prefixCovers
  rw [prefixDir_eq, Bool.or_eq_true, List.isPrefixOf_iff_prefix, beq_iff_eq, List.append_left_inj]
  constructor
  · rintro (⟨w, hw⟩ | h)
    · exact .inr ⟨w, by rw [← hw]; simp⟩
    · exact .inl h
  · rintro (h | ⟨w, hw⟩)
    · exact .inr h
    · exact .inl ⟨w, by rw [hw]; simp⟩

/-- A prefix grant covers only paths whose first segments are its directory's. -/
theorem prefix_covers_segments {pre path : Str} (h : prefixCovers pre path = true) :
    ∃ t, split path = split (prefixBase pre) ++ t := by
  rcases prefixCovers_iff.mp h with rfl | ⟨w, rfl⟩
  · exact ⟨[], by simp⟩
  · exact ⟨split w, split_append_slash _ _⟩

/-- **A prefix grant is no wider than a reach rule `Q/**`**: for a directory `Q` without `*` or `?`,
it covers `Q` itself and only paths the glob `Q/**` matches. -/
theorem prefix_grant_is_globstar {pre path : Str} (hq : (prefixBase pre).all plainChar)
    (h : prefixCovers pre path = true) :
    path = prefixBase pre ∨ Lang csEq (prefixBase pre ++ ['/', '*', '*']) path := by
  rcases prefixCovers_iff.mp h with e | ⟨w, rfl⟩
  · exact .inl e
  · exact .inr (globstar_crosses hq w)

/-- **A covered path can't escape its prefix upstream**: a canonical path a prefix grant covers
(for a directory without `%`) still has the directory's segments first as an upstream that
decodes and resolves dot segments reads it. -/
theorem prefix_no_escape {pre path : Str} (hp : plainOk path = true) (hpct : '%' ∉ prefixBase pre)
    (h : prefixCovers pre path = true) :
    ∃ t, resolve (split (decode path)) = split (prefixBase pre) ++ t := by
  obtain ⟨t, ht⟩ := prefix_covers_segments h
  refine ⟨t.map decode, ?_⟩
  rw [(upstream_eq hp).1, ht, List.map_append]
  congr 1
  have : ∀ s ∈ split (prefixBase pre), decode s = s := fun s hs =>
    decode_of_no_pct (fun e => hpct (mem_of_mem_split hs e))
  clear ht h
  generalize split (prefixBase pre) = qs at this ⊢
  induction qs with
  | nil => rfl
  | cons s ss ih =>
    simp only [List.map_cons, this s List.mem_cons_self]
    rw [ih (fun x hx => this x (List.mem_cons_of_mem _ hx))]

end Wicket
