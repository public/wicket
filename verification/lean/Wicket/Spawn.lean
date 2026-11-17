import Wicket.Subset

/-!
# What a spawned box may call and hear, and the spawn its node decides (#322)

Three gaps in `Subset.lean`, closed:

- **The model allowlist** (`zone.llm.models`, #366): `subset::check` admits a child's list only if
  each entry is covered by one of its parent's (`model_violations`, with `model_covers`).
  `check_models`: every model an admitted child may call (`LlmSpec::allows_model`), its parent may,
  when the parent's patterns are well formed (a name, or a prefix ending in its only `*`, as
  `check_models` in the manifest requires; `abc**` would cover `abc*` and not what it allows).
- **Who a box hears from** (`accept_from`, #250, #411): `manifest::accepts` lets a sender in by its
  zone, or by its principal id for an entry that is one (`is_principal_entry`: it has `://`).
  `accept_narrow`: a child admitted by `check` hears only from its parent's own zone or from a
  sender its parent hears from.
- **The spawn a node decides** (#164): `plan_child`'s violations are `subset::check`'s, the
  parent's token must allow the start (`peek_spawn`), and `derive_child` appends a spawn block with
  the child's ceiling to the parent's base token (`Token::attenuate`), ending no later than the
  parent's authority. A token of first-party blocks decides as `chainVerdict` (oracle 2 in
  `oracles.rs`, and the oracle here against minted tokens): forbidden if a block forbids, allowed if
  every block allows, otherwise it needs a grant. `attenuate_allow`, `attenuate_forbid`,
  `attenuate_live`, `attenuate_spawns`: an appended block never widens. `node_spawn_within`: a
  child its node starts is `Within` its parent's zone, its token allows nothing its parent's
  doesn't, forbids all it forbids, lives no longer, and allows no start it doesn't.

The Biscuit evaluator itself stays outside the spec: `chainVerdict` is what it is tested against.
-/

namespace Wicket

/-! ## Models -/

theorem startsWith_nil (s : Str) : startsWith s [] = true := by
  cases s <;> rfl

theorem startsWith_trans : ∀ (q s p : Str), startsWith s p = true → startsWith p q = true → startsWith s q = true
  | [], s, _, _, _ => startsWith_nil s
  | _ :: _, _, [], _, h2 => by simp [startsWith] at h2
  | _ :: _, [], _ :: _, h1, _ => by simp [startsWith] at h1
  | c :: q, a :: s, b :: p, h1, h2 => by
    simp only [startsWith, Bool.and_eq_true, beq_iff_eq] at h1 h2 ⊢
    exact ⟨h1.1.trans h2.1, startsWith_trans q s p h1.2 h2.2⟩

/-- A prefix without `*` of `m ++ "*"` is a prefix of `m`. -/
theorem startsWith_snoc_star : ∀ (p m : Str), '*' ∉ p → startsWith (m ++ ['*']) p = true → startsWith m p = true
  | [], m, _, _ => startsWith_nil m
  | b :: p, [], hp, h => by
    simp only [List.nil_append, startsWith, Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨rfl, -⟩ := h
    simp at hp
  | b :: p, a :: m, hp, h => by
    simp only [List.cons_append, startsWith, Bool.and_eq_true, beq_iff_eq] at h ⊢
    exact ⟨h.1, startsWith_snoc_star p m (fun hm => hp (by simp [hm])) h.2⟩

theorem stripStar_eq : ∀ (q p : Str), stripStar q = some p → q = p ++ ['*']
  | [], _, h => by simp [stripStar] at h
  | [c], p, h => by
    simp only [stripStar] at h
    split at h
    · rename_i hc
      cases h
      subst hc
      rfl
    · cases h
  | c :: d :: s, p, h => by
    simp only [stripStar] at h
    split at h
    · rename_i r hr
      cases h
      rw [stripStar_eq _ _ hr]
      rfl
    · cases h

/-- A well-formed model pattern: a name, or a prefix ending in its only `*` (`check_models`). -/
def PatOk (q : Str) : Prop := ∀ p, stripStar q = some p → '*' ∉ p

/-- **Coverage composes** for a well-formed outer pattern. -/
theorem modelCovers_trans {q m n : Str} (hq : PatOk q) (h1 : modelCovers q m = true)
    (h2 : modelCovers m n = true) : modelCovers q n = true := by
  unfold modelCovers at h1 h2 ⊢
  revert h1
  cases hsq : stripStar q with
  | none =>
    intro h1
    have e : q = m := beq_iff_eq.mp h1
    subst e
    rw [hsq] at h2
    exact h2
  | some p =>
    intro h1
    have h1' : startsWith m p = true := h1
    revert h2
    cases hsm : stripStar m with
    | none =>
      intro h2
      have e : m = n := beq_iff_eq.mp h2
      subst e
      exact h1'
    | some r =>
      intro h2
      have h2' : startsWith n r = true := h2
      rw [stripStar_eq _ _ hsm] at h1'
      exact startsWith_trans p n r h2' (startsWith_snoc_star p r (hq p hsq) h1')

/-- Every model a child route admitted by `llmModelsOk` may call, its parent's may. -/
theorem llmModels_narrow {cl pl : Llm} (hwf : ∀ ms, pl.models = some ms → ∀ q ∈ ms, PatOk q)
    (h : llmModelsOk cl pl = true) {n : Str} (hn : cl.allowsModel n = true) : pl.allowsModel n = true := by
  unfold llmModelsOk at h
  unfold Llm.allowsModel at hn ⊢
  revert h hn
  cases hp : pl.models with
  | none => intro _ _; rfl
  | some pm =>
    cases hc : cl.models with
    | none => intro h _; exact absurd h (by simp)
    | some cm =>
      intro h hn
      have h' : cm.all (fun m => pm.any (fun q => modelCovers q m)) = true := h
      have hn' : cm.any (fun q => modelCovers q n) = true := hn
      simp only [List.all_eq_true, List.any_eq_true] at h' hn'
      obtain ⟨m, hm, hmn⟩ := hn'
      obtain ⟨q, hq, hqm⟩ := h' m hm
      show pm.any (fun q => modelCovers q n) = true
      exact List.any_eq_true.mpr ⟨q, hq, modelCovers_trans (hwf pm hp q hq) hqm hmn⟩

/-- The models a zone's boxes may call: none without a model route. -/
def Zone.allowsModel (z : Zone) (n : Str) : Bool :=
  match z.llm with
  | some l => l.allowsModel n
  | none => false

/-- Every pattern of a zone's model list is well formed (what manifest loading checks). -/
def Zone.ModelsWf (z : Zone) : Prop := ∀ l, z.llm = some l → ∀ ms, l.models = some ms → ∀ q ∈ ms, PatOk q

/-- A zone `c` calls no model `p` may not. -/
def ModelsWithin (c p : Zone) : Prop := ∀ n, c.allowsModel n = true → p.allowsModel n = true

theorem modelsWithin_trans {g c p : Zone} (h1 : ModelsWithin g c) (h2 : ModelsWithin c p) : ModelsWithin g p :=
  fun n h => h2 n (h1 n h)

/-- **A spawned zone admitted by `subset::check` calls no model its parent may not.** -/
theorem check_models {a : Ask} {b : Bounds} (h : check a b = true) (hwf : b.zone.ModelsWf) :
    ModelsWithin a.zone b.zone := by
  intro n hn
  have hw := check_within h
  simp only [check, Bool.and_eq_true] at h
  have hm : modelsOk a.zone b.zone = true := h.2
  unfold Zone.allowsModel at hn ⊢
  unfold modelsOk at hm
  revert hn hm
  cases hc : a.zone.llm with
  | none => intro hn _; exact absurd hn (by simp)
  | some cl =>
    obtain ⟨pl, hp, -⟩ := hw.llm cl hc
    rw [hp]
    intro hn hm
    exact llmModels_narrow (hwf pl hp) hm hn

/-- Two admitted spawns: the grandchild calls no model its grandparent may not. -/
theorem grandchild_models {a1 a2 : Ask} {b1 b2 : Bounds} (h1 : check a1 b1 = true) (h2 : check a2 b2 = true)
    (hb : b2.zone = a1.zone) (hwf1 : b1.zone.ModelsWf) (hwf2 : a1.zone.ModelsWf) : ModelsWithin a2.zone b1.zone :=
  modelsWithin_trans (hb ▸ check_models h2 (hb ▸ hwf2)) (check_models h1 hwf1)

/-! ## Who a box accepts messages from -/

/-- `str::contains`: `sub` occurs in `s`. -/
def infixOf (sub : Str) : Str → Bool
  | [] => sub.isEmpty
  | c :: s => startsWith (c :: s) sub || infixOf sub s

/-- `is_principal_entry`: an id (`spiffe://…`), not a zone. -/
def isPrincipalEntry (e : Str) : Bool := infixOf [':', '/', '/'] e

/-- `manifest::accepts(accept_from, zone, principal)`: an entry names the sender's zone, or (a
principal entry) its principal id, when the caller knows it. -/
def accepts (list : List Str) (zone : Str) (principal : Option Str) : Bool :=
  list.any (fun a => if isPrincipalEntry a then principal == some a else a == zone)

/-- **A spawned zone hears from no one new**: a sender a child admitted by `acceptOk` accepts is
in its parent's own zone, or one its parent accepts. (A zone's name is never a principal entry.) -/
theorem accept_narrow {c p : Zone} (h : acceptOk c p = true) (hname : isPrincipalEntry p.name = false)
    {zone : Str} {pr : Option Str} (ha : accepts c.acceptFrom zone pr = true) :
    zone = p.name ∨ accepts p.acceptFrom zone pr = true := by
  simp only [accepts, List.any_eq_true] at ha ⊢
  obtain ⟨e, he, hm⟩ := ha
  simp only [acceptOk, List.all_eq_true, Bool.or_eq_true, beq_iff_eq, List.contains_iff_mem] at h
  rcases h e he with rfl | hp
  · left
    simp [hname] at hm
    first | exact hm.symm | exact hm
  · exact Or.inr ⟨e, hp, hm⟩

theorem check_accepts {a : Ask} {b : Bounds} (h : check a b = true) (hname : isPrincipalEntry b.zone.name = false)
    {zone : Str} {pr : Option Str} (ha : accepts a.zone.acceptFrom zone pr = true) :
    zone = b.zone.name ∨ accepts b.zone.acceptFrom zone pr = true := by
  simp only [check, Bool.and_eq_true] at h
  exact accept_narrow h.1.1.1.2 hname ha

/-! ## A token's blocks -/

/-- How a token of first-party blocks decides a request: forbidden if a block forbids it, allowed if
every block allows it, otherwise it needs a grant. -/
def chainVerdict (zs : List Zone) (o : Op) : Verdict :=
  if zs.any (fun z => decide (evaluate z o = .forbidden)) then .forbidden
  else if zs.all (fun z => decide (evaluate z o = .allow)) then .allow
  else .needsGrant

theorem chain_allow_iff {zs : List Zone} {o : Op} :
    chainVerdict zs o = .allow ↔ ∀ z ∈ zs, evaluate z o = .allow := by
  unfold chainVerdict
  constructor
  · intro h
    split at h
    · cases h
    · split at h
      · rename_i hall
        simpa only [List.all_eq_true, decide_eq_true_eq] using hall
      · cases h
  · intro h
    have hnf : zs.any (fun z => decide (evaluate z o = .forbidden)) = false := by
      simp only [List.any_eq_false, decide_eq_true_eq]
      intro z hz hf
      rw [h z hz] at hf
      cases hf
    have hall : zs.all (fun z => decide (evaluate z o = .allow)) = true := by
      simp only [List.all_eq_true, decide_eq_true_eq]
      exact h
    simp [hnf, hall]

theorem chain_forbid_iff {zs : List Zone} {o : Op} :
    chainVerdict zs o = .forbidden ↔ ∃ z ∈ zs, evaluate z o = .forbidden := by
  unfold chainVerdict
  constructor
  · intro h
    split at h
    · rename_i hany
      simpa only [List.any_eq_true, decide_eq_true_eq] using hany
    · split at h <;> cases h
  · intro h
    have hany : zs.any (fun z => decide (evaluate z o = .forbidden)) = true := by
      simpa only [List.any_eq_true, decide_eq_true_eq] using h
    simp [hany]

/-- What a box starts, as `peek_spawn` asks its token: the image entry, isolation and limits. -/
structure SpawnAsk where
  image : Str
  isolation : Nat
  memory : Nat
  cpus : Nat
  pids : Nat
  timeout : Nat

/-- A first-party block of a box's token (block 0, or a spawn block): its zone's ceiling, when its
authority ends, and the starts it allows. -/
structure Block where
  zone : Zone
  ends : Nat
  spawns : SpawnAsk → Bool

def tokenVerdict (t : List Block) (o : Op) : Verdict := chainVerdict (t.map (·.zone)) o

/-- Every block's authority lasts past `now`. -/
def tokenLive (t : List Block) (now : Nat) : Bool := t.all (fun b => decide (now < b.ends))

/-- Every block allows the start. -/
def tokenSpawns (t : List Block) (s : SpawnAsk) : Bool := t.all (fun b => b.spawns s)

/-- `Token::attenuate`: a spawn block appended. -/
def attenuate (t : List Block) (b : Block) : List Block := t ++ [b]

/-- **An appended block allows nothing the token didn't**, and nothing its own ceiling doesn't. -/
theorem attenuate_allow {t : List Block} {b : Block} {o : Op} (h : tokenVerdict (attenuate t b) o = .allow) :
    tokenVerdict t o = .allow ∧ evaluate b.zone o = .allow := by
  simp only [tokenVerdict, attenuate, List.map_append, List.map_cons, List.map_nil] at h ⊢
  rw [chain_allow_iff] at h ⊢
  exact ⟨fun y hy => h y (by simp [hy]), h b.zone (by simp)⟩

/-- **An appended block unforbids nothing.** -/
theorem attenuate_forbid {t : List Block} {b : Block} {o : Op} (h : tokenVerdict t o = .forbidden) :
    tokenVerdict (attenuate t b) o = .forbidden := by
  simp only [tokenVerdict, attenuate, List.map_append, List.map_cons, List.map_nil] at h ⊢
  rw [chain_forbid_iff] at h ⊢
  obtain ⟨z, hz, hf⟩ := h
  exact ⟨z, by simp [hz], hf⟩

/-- **An appended block outlives no block of the token.** -/
theorem attenuate_live {t : List Block} {b : Block} {now : Nat} (h : tokenLive (attenuate t b) now = true) :
    tokenLive t now = true ∧ now < b.ends := by
  simp only [tokenLive, attenuate, List.all_eq_true, decide_eq_true_eq] at h ⊢
  exact ⟨fun y hy => h y (by simp [hy]), h b (by simp)⟩

/-- **An appended block allows no start the token didn't.** -/
theorem attenuate_spawns {t : List Block} {b : Block} {s : SpawnAsk} (h : tokenSpawns (attenuate t b) s = true) :
    tokenSpawns t s = true := by
  simp only [tokenSpawns, attenuate, List.all_eq_true] at h ⊢
  exact fun y hy => h y (by simp [hy])

/-! ## The spawn a node decides -/

/-- What a node has when a box asks it to start a child (#164): the parent's zone and what it has
left (`plan_child`'s `Bounds`, from its replica and the box's budget slice), the parent's base token
(block 0 and spawn blocks, without grants), the start `peek_spawn` asks about, the child's ceiling's
starts, and when the child's authority would end by its own timeout. -/
structure NodeAsk where
  ask : Ask
  bounds : Bounds
  base : List Block
  spawn : SpawnAsk
  childSpawns : SpawnAsk → Bool
  wantUntil : Nat
  parentUntil : Nat

/-- `nodegw::spawn` on a node: admitted by `subset::check` (anything else goes to the control host),
the parent's token allows the start (`peek_spawn`), and `derive_child` appends the child's block,
whose authority ends no later than its parent's (`start_child`). -/
def nodeSpawn (n : NodeAsk) : Option (List Block) :=
  if check n.ask n.bounds && tokenSpawns n.base n.spawn then
    some (attenuate n.base { zone := n.ask.zone, ends := min n.wantUntil n.parentUntil, spawns := n.childSpawns })
  else none

/-- **A child its node starts stays within its parent**: its zone is `Within` the parent's, its
token allows nothing the parent's doesn't (nor anything its own zone doesn't), forbids all the
parent's forbids, lives no longer than the parent's authority, and allows no start the parent's
doesn't. -/
theorem node_spawn_within {n : NodeAsk} {t : List Block} (h : nodeSpawn n = some t) :
    Within n.ask.zone n.bounds.zone ∧
    (∀ o, tokenVerdict t o = .allow → tokenVerdict n.base o = .allow ∧ evaluate n.ask.zone o = .allow) ∧
    (∀ o, tokenVerdict n.base o = .forbidden → tokenVerdict t o = .forbidden) ∧
    (∀ now, tokenLive t now = true → tokenLive n.base now = true ∧ now < n.parentUntil) ∧
    (∀ s, tokenSpawns t s = true → tokenSpawns n.base s = true) := by
  unfold nodeSpawn at h
  split at h
  · rename_i hc
    cases h
    simp only [Bool.and_eq_true] at hc
    refine ⟨check_within hc.1, fun o ho => attenuate_allow ho, fun o ho => attenuate_forbid ho,
      fun now hl => ?_, fun s hs => attenuate_spawns hs⟩
    obtain ⟨hb, hu⟩ := attenuate_live hl
    exact ⟨hb, Nat.lt_of_lt_of_le hu (Nat.min_le_right _ _)⟩
  · cases h

end Wicket
