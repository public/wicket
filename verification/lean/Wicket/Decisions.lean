/-!
# Decisions wicket-core makes in pure functions (#322; moved there for Kani, #325)

Each definition restates one function, and the oracle (`Oracle.lean`, `lean_oracle.rs`) checks the
Rust against it on generated cases:

- `op::is_public_ip` (the SSRF guard): an address is public exactly outside the never-public blocks;
- `quota::not_after_for` and `token_allows` (#342): a node's token ends a grant at the ledger's
  millisecond;
- `authority::agent_term_refusal`: each `agents:` rule lifts exactly its own refusal;
- `escalation::check_escalatable` and `needs_grant`: a refusal is a grant request only if every
  failed check is a known escalatable one (fail-closed);
- `quota::take_use`: a counted grant never goes below zero;
- `quota::money_fits`: a reservation fits exactly within the limits;
- `quota::SpawnLimits::admits`: a spawn within an admitted one is admitted.

Numbers are `Int` and `Nat`, so the spec has no overflow: the Rust's exactness (sums in `i128`,
checked arithmetic) is what the oracle and Kani hold it to.
-/

namespace Wicket

/-! ## The SSRF guard: `op::is_public_ip` -/

/-- Whether address `a` is in the block of network `b.1` and prefix length `b.2`, of `bits` bits. -/
def inBlock (bits a : Nat) (b : Nat × Nat) : Bool := a / 2 ^ (bits - b.2) == b.1 / 2 ^ (bits - b.2)

/-- IPv4 blocks that are never public (IANA's special-purpose registry, multicast, 240/4 with the
broadcast address, and Azure's WireServer, #366): the table `proofs/ip_blocks.rs` holds too. -/
def v4Blocks : List (Nat × Nat) :=
  [(0x00000000, 8), (0x0a000000, 8), (0x64400000, 10), (0x7f000000, 8), (0xa9fe0000, 16),
   (0xac100000, 12), (0xc0000000, 24), (0xc0000200, 24), (0xc0586300, 24), (0xc0a80000, 16),
   (0xc6120000, 15), (0xc6336400, 24), (0xcb007100, 24), (0xe0000000, 4), (0xf0000000, 4),
   (0xa83f8110, 32)]

/-- IPv6 blocks that are never public: ::/96 (loopback, unspecified, IPv4-compatible), IPv4-mapped,
NAT64 (/32), discard, 2001::/23 (Teredo among them), documentation, 6to4, unique-local,
link-local, site-local, multicast. -/
def v6Blocks : List (Nat × Nat) :=
  [(0, 96), (0xffff00000000, 96), (0x0064ff9b000000000000000000000000, 32),
   (0x01000000000000000000000000000000, 64), (0x20010000000000000000000000000000, 23),
   (0x20010db8000000000000000000000000, 32), (0x20020000000000000000000000000000, 16),
   (0xfc000000000000000000000000000000, 7), (0xfe800000000000000000000000000000, 10),
   (0xfec00000000000000000000000000000, 10), (0xff000000000000000000000000000000, 8)]

/-- `is_public_ip` of an IPv4 address (as a number below 2^32). -/
def isPublic4 (a : Nat) : Bool := !(v4Blocks.any (inBlock 32 a))

/-- `is_public_ip` of an IPv6 address (as a number below 2^128). -/
def isPublic6 (a : Nat) : Bool := !(v6Blocks.any (inBlock 128 a))

/-- An address in a never-public block is never public. -/
theorem in_block_not_public4 {a : Nat} {b : Nat × Nat} (hb : b ∈ v4Blocks) (h : inBlock 32 a b = true) :
    isPublic4 a = false := by
  have hany : v4Blocks.any (inBlock 32 a) = true := List.any_eq_true.mpr ⟨b, hb, h⟩
  unfold isPublic4
  rw [hany]
  rfl

theorem in_block_not_public6 {a : Nat} {b : Nat × Nat} (hb : b ∈ v6Blocks) (h : inBlock 128 a b = true) :
    isPublic6 a = false := by
  have hany : v6Blocks.any (inBlock 128 a) = true := List.any_eq_true.mpr ⟨b, hb, h⟩
  unfold isPublic6
  rw [hany]
  rfl

/-- The cloud metadata addresses: 169.254.169.254, Azure's 168.63.129.16, and 169.254.169.254
behind IPv4-mapped, NAT64 and 6to4 forms. -/
theorem metadata_never_public :
    isPublic4 0xa9fea9fe = false ∧ isPublic4 0xa83f8110 = false ∧
    isPublic6 0xffffa9fea9fe = false ∧ isPublic6 0x0064ff9b0000000000000000a9fea9fe = false ∧
    isPublic6 0x2002a9fea9fe00000000000000000000 = false := by decide

/-- An address just past the documentation block 192.0.2.0/24 is public. -/
theorem neighbour_public : isPublic4 0xc0000301 = true := by decide

/-! ## A grant's end in a node's token (#342): `quota::not_after_for`, `token_secs`, `token_allows` -/

/-- `token_secs`: a request's time in the token, floored to the second, 0 before the epoch. -/
def tokenSecs (nowMs : Int) : Int := if nowMs < 0 then 0 else nowMs / 1000

/-- `not_after_for`: `expires_at - 1`, and 0 for an end at or before the epoch. -/
def notAfterFor (e : Int) : Int := if e - 1 < 0 then 0 else e - 1

/-- `token_allows`: the token's check, `time <= not_after`. -/
def tokenAllows (notAfter nowMs : Int) : Bool := decide (tokenSecs nowMs ≤ notAfter)

/-- **The token and the ledger end a grant at the same millisecond** (Kani:
`a_token_ends_with_its_grant_through_2106`, `a_token_allows_a_reading_before_the_epoch`): for every
grant end after the epoch and every clock reading, the token allows exactly while the ledger's
half-open grant is live. -/
theorem token_ends_at_ledger_ms (e nowMs : Int) (he : 1 ≤ e) :
    tokenAllows (notAfterFor e) nowMs = true ↔ nowMs < e * 1000 := by
  unfold tokenAllows tokenSecs notAfterFor
  simp only [decide_eq_true_eq]
  split <;> split <;> omega

/-! ## Agents' grant terms: `authority::agent_term_refusal` -/

inductive TermRefusal where
  | zoneWide
  | pfx
  | unbounded
  | gitPush
  deriving DecidableEq, Repr

/-- `agent_term_refusal(rules, shape)`: rules first (whole zone, prefix, no number of uses, a git
push's window), then the shape's terms, in `agent_terms`' order. -/
def agentTermRefusal (rZone rPfx rUnb rPush sZone sPfx sUnb sPush : Bool) : Option TermRefusal :=
  if sZone && !rZone then some .zoneWide
  else if sPfx && !rPfx then some .pfx
  else if sUnb && !rUnb then some .unbounded
  else if sPush && !rPush then some .gitPush
  else none

/-- The default rules refuse every refusal-shaped grant `agent_terms` refused before the rules
existed, and nothing else (Kani: `default_agent_rules_refuse_what_agent_terms_did`). -/
theorem default_rules_refuse (sZone sPfx sUnb sPush : Bool) :
    (agentTermRefusal false false false false sZone sPfx sUnb sPush).isSome = (sZone || sPfx || sUnb || sPush) := by
  cases sZone <;> cases sPfx <;> cases sUnb <;> cases sPush <;> decide

/-- Each rule lifts exactly its own refusal (Kani: `each_agent_rule_lifts_only_its_refusal`). -/
theorem each_rule_lifts_its_own (rZone rPfx rUnb rPush sZone sPfx sUnb sPush : Bool) :
    (agentTermRefusal rZone rPfx rUnb rPush sZone sPfx sUnb sPush).isSome =
      ((sZone && !rZone) || (sPfx && !rPfx) || (sUnb && !rUnb) || (sPush && !rPush)) := by
  cases rZone <;> cases rPfx <;> cases rUnb <;> cases rPush <;>
    cases sZone <;> cases sPfx <;> cases sUnb <;> cases sPush <;> decide

/-! ## When a refusal is a grant request: `escalation` -/

/-- `check_escalatable`: a `check if` that reads reach or risk, never the org policy. -/
def checkEscalatable (one policy host risk approved : Bool) : Bool := one && !policy && (host || risk || approved)

/-- A check that reads the org policy is never escalatable (Kani:
`an_org_policy_check_is_never_escalatable`). -/
theorem org_policy_never_escalatable (one host risk approved : Bool) :
    checkEscalatable one true host risk approved = false := by
  cases one <;> cases host <;> cases risk <;> cases approved <;> decide

/-- A failed check, as the decision sees it: the node's own, or a token check whose class is known
escalatable (`some true`), known hard (`some false`) or unknown (`none`). -/
inductive Failed where
  | node
  | block (escalatable : Option Bool)
  deriving DecidableEq, Repr

def Failed.soft : Failed → Bool
  | .block (some true) => true
  | _ => false

/-- The decision: a grant request exactly when at least one check failed and every one is soft. -/
def refusalNeedsGrant (fs : List Failed) : Bool := !fs.isEmpty && fs.all Failed.soft

/-- `needs_grant(hard, soft)`, on the counts `Loaded::classify` makes. -/
def needsGrantCounts (hard soft : Nat) : Bool := hard == 0 && 0 < soft

/-- Fail-closed (Kani: `a_refusal_needs_a_grant_only_if_every_failure_is_escalatable`): a refusal
naming no check, or failing a node check or a check of unknown class, is never a grant request. -/
theorem needs_grant_fail_closed (fs : List Failed) :
    refusalNeedsGrant [] = false ∧ refusalNeedsGrant (fs ++ [.node]) = false ∧ refusalNeedsGrant (fs ++ [.block none]) = false := by
  refine ⟨rfl, ?_, ?_⟩ <;> simp [refusalNeedsGrant, Failed.soft, List.all_append]

/-! ## Counted grants: `quota::take_use` -/

/-- `take_use`: `none` refuses; `some left` accepts, with `left` uses after it. -/
def takeUse : Option Int → Option (Option Int)
  | none => some none
  | some n => if 0 < n then some (some (n - 1)) else none

/-- A use takes exactly one, and never a count below zero (Kani: `a_use_never_takes_a_grant_below_zero`). -/
theorem take_use_never_below_zero {n m : Int} (h : takeUse (some n) = some (some m)) : 0 ≤ m ∧ m = n - 1 := by
  simp only [takeUse] at h
  split at h
  · injection h with h
    injection h with h
    omega
  · contradiction

/-- A counted grant at zero (or below) is refused. -/
theorem take_use_refused_at_zero {n : Int} (h : n ≤ 0) : takeUse (some n) = none := by
  simp only [takeUse]
  split
  · omega
  · rfl

/-! ## The money check: `quota::money_fits` -/

inductive MoneyOver where
  | hourly
  | total
  deriving DecidableEq, Repr

/-- `money_fits(reserved, new, max)`: the hourly limit first. -/
def moneyFits (rh rt nh nt mh mt : Int) : Option MoneyOver :=
  if mh < rh + nh then some .hourly else if mt < rt + nt then some .total else none

/-- A reservation fits exactly when both sums are within their limits (Kani:
`money_is_accepted_exactly_within_the_limits`). -/
theorem money_fits_exactly (rh rt nh nt mh mt : Int) :
    moneyFits rh rt nh nt mh mt = none ↔ (rh + nh ≤ mh ∧ rt + nt ≤ mt) := by
  unfold moneyFits
  split
  · constructor
    · intro h; contradiction
    · intro h; omega
  · split
    · constructor
      · intro h; contradiction
      · intro h; omega
    · constructor
      · intro _; omega
      · intro _; rfl

/-! ## The org policy's spawn ceiling: `quota::SpawnLimits::admits` -/

def capOk (cap : Option Int) (x : Int) : Bool :=
  match cap with
  | none => true
  | some n => decide (x ≤ n)

def floorOk (fl : Option Int) (x : Int) : Bool :=
  match fl with
  | none => true
  | some n => decide (n ≤ x)

/-- `SpawnLimits::admits(ask)`: the isolation floor, then the caps on memory, CPUs, processes and
time. -/
def spawnAdmits (minIso maxMem maxCpus maxPids maxTimeout : Option Int) (iso mem cpus pids timeout : Int) : Bool :=
  floorOk minIso iso && capOk maxMem mem && capOk maxCpus cpus && capOk maxPids pids && capOk maxTimeout timeout

theorem capOk_mono {c : Option Int} {x y : Int} (h : capOk c x = true) (hy : y ≤ x) : capOk c y = true := by
  cases c with
  | none => rfl
  | some n =>
    simp only [capOk, decide_eq_true_eq] at h ⊢
    omega

theorem floorOk_mono {c : Option Int} {x y : Int} (h : floorOk c x = true) (hy : x ≤ y) : floorOk c y = true := by
  cases c with
  | none => rfl
  | some n =>
    simp only [floorOk, decide_eq_true_eq] at h ⊢
    omega

/-- A spawn that asks for no more than an admitted one (isolation at least as strong, no more of any
resource) is admitted too (Kani: `a_spawn_ceiling_admits_what_is_within_it_and_tighter_admits_less`). -/
theorem spawn_within_admitted {minIso maxMem maxCpus maxPids maxTimeout : Option Int}
    {iso mem cpus pids timeout iso' mem' cpus' pids' timeout' : Int}
    (h : spawnAdmits minIso maxMem maxCpus maxPids maxTimeout iso mem cpus pids timeout = true)
    (hi : iso ≤ iso') (hm : mem' ≤ mem) (hc : cpus' ≤ cpus) (hp : pids' ≤ pids) (ht : timeout' ≤ timeout) :
    spawnAdmits minIso maxMem maxCpus maxPids maxTimeout iso' mem' cpus' pids' timeout' = true := by
  simp only [spawnAdmits, Bool.and_eq_true] at h ⊢
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := h
  exact ⟨⟨⟨⟨floorOk_mono h1 hi, capOk_mono h2 hm⟩, capOk_mono h3 hc⟩, capOk_mono h4 hp⟩, capOk_mono h5 ht⟩

end Wicket
