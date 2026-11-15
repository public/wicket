import Lean.Data.Json
import Wicket

/-!
# The spec as an oracle (#322)

`lake env lean --run Oracle.lean cases.json` reads a file of cases and prints one decision per case,
one per line, in order. wicket-authz's `lean_oracle` test writes the cases (its fixtures and
generated ones), runs this, and compares every line with what the Rust code decided.

Input: `{"zones": [zone…], "cases": [case…]}`. A case is one of
- `{"kind": "eval", "zone": i, "op": {method, host, path, risk, unreachable}}` → `allow`,
  `forbidden` or `needs_grant`;
- `{"kind": "check", "parent": i, "child": j, "bounds": {…}, "max_children": n}` → `true`/`false`;
- `{"kind": "reach_within", "outer": i, "inner": j}` → `true`/`false`;
- `{"kind": "host", "pattern": p, "host": h}` → `true`/`false`;
- `{"kind": "canon", "path": pq}` → the canonical path as a JSON string, or `null`.

Every string is read as its UTF-8 bytes (`bytesOf`): the spec is over any alphabet, and wicket's
matchers and checks work on bytes.

A case whose globs are outside the spec's language (classes, alternations, escapes) prints
`unsupported`.
-/

open Lean Wicket

/-- A string as the spec reads it: its UTF-8 bytes, one symbol each. globset matches bytes (its
regexes are `(?-u)`: `?` is one byte), and `canonical_path` checks bytes. -/
def bytesOf (s : String) : Str := s.toUTF8.toList.map (fun b => Char.ofNat b.toNat)

def stringOf (p : Str) : String :=
  (String.fromUTF8? (ByteArray.mk (p.map (fun c => c.toNat.toUInt8)).toArray)).getD "<not UTF-8>"

def jStr (j : Json) (k : String) : Except String Str := do
  let s ← j.getObjValAs? String k
  return bytesOf s

def jNat (j : Json) (k : String) : Except String Nat := j.getObjValAs? Nat k

def jBool (j : Json) (k : String) : Except String Bool := j.getObjValAs? Bool k

def jOptNat (j : Json) (k : String) : Except String (Option Nat) := do
  match j.getObjVal? k with
  | .ok .null => return none
  | .ok v => return some (← v.getNat?)
  | .error _ => return none

def jStrs (j : Json) (k : String) : Except String (List Str) := do
  let a ← j.getObjValAs? (Array String) k
  return a.toList.map bytesOf

def jArr (j : Json) (k : String) : Except String (List Json) := do
  let a ← (← j.getObjVal? k).getArr?
  return a.toList

def parseReach (j : Json) : Except String Reach :=
  return { host := ← jStr j "host", methods := ← jStrs j "methods", paths := ← jStrs j "paths",
           dangerous := ← jBool j "dangerous" }

def parseForbid (j : Json) : Except String Forbid :=
  return { host := ← jStr j "host", paths := ← jStrs j "paths" }

def parseInject (j : Json) : Except String Inject := do
  let a ← j.getArr?
  let s := fun (i : Nat) => do
    let v ← (a[i]?).elim (.error "inject") pure
    return bytesOf (← v.getStr?)
  return { host := ← s 0, header := ← s 1, format := ← s 2, secret := ← s 3 }

def parseLlm (j : Json) : Except String (Option Llm) := do
  match j with
  | .null => return none
  | _ => return some { provider := ← jStr j "provider", secret := ← jStr j "secret", upstream := ← jStr j "upstream",
                       serverTools := ← jBool j "server_tools", maxRequests := ← jNat j "max_requests",
                       maxOutput := ← jNat j "max_output", maxInput := ← jOptNat j "max_input" }

/-- An `f32` sent as `{m, e}` (`m × 2^e`), as an integer times 2^160. -/
def parseCpus (j : Json) : Except String (Option Int) := do
  match j with
  | .null => return none
  | _ =>
    let m ← j.getObjValAs? Int "m"
    let e ← j.getObjValAs? Int "e"
    let k := 160 + e
    if k < 0 then throw "cpus exponent" else return some (m * 2 ^ k.toNat)

def parseZone (j : Json) : Except String Zone := do
  let lim ← j.getObjVal? "limits"
  let esc ← j.getObjVal? "escalation"
  return {
    name := ← jStr j "name", isolation := ← jNat j "isolation",
    reach := ← (← jArr j "reach").mapM parseReach, forbid := ← (← jArr j "forbid").mapM parseForbid,
    hide := ← jBool j "hide", wildcardsForbid := ← jBool j "wildcards_forbid", maxNames := ← jNat j "max_names",
    inject := ← (← jArr j "inject").mapM parseInject, llm := ← parseLlm (← j.getObjVal? "llm"),
    escalation := { request := ← jBool esc "request", grant := ← jBool esc "grant" },
    limits := { memory := ← jOptNat lim "memory", cpus := ← parseCpus (← lim.getObjVal? "cpus"),
                pids := ← jNat lim "pids", output := ← jOptNat lim "output", stopOnFull := ← jBool lim "stop_on_full",
                timeout := ← jOptNat lim "timeout_ms", authority := ← jOptNat lim "authority_ms" },
    acceptFrom := ← jStrs j "accept_from" }

def Wicket.Zone.supported (z : Zone) : Bool :=
  z.reach.all (fun r => r.paths.all Wicket.supported) && z.forbid.all (fun f => f.paths.all Wicket.supported)

def verdictName : Verdict → String
  | .allow => "allow"
  | .forbidden => "forbidden"
  | .needsGrant => "needs_grant"

def zoneAt (zs : Array Zone) (c : Json) (k : String) : Except String Zone := do
  let i ← jNat c k
  (zs[i]?).elim (.error s!"no zone {i}") pure

def decideCase (zs : Array Zone) (c : Json) : Except String String := do
  let kind ← c.getObjValAs? String "kind"
  match kind with
  | "eval" =>
    let z ← zoneAt zs c "zone"
    let o ← c.getObjVal? "op"
    let op : Op := { method := ← jStr o "method", host := ← jStr o "host", path := ← jStr o "path",
                     risk := ← jNat o "risk", unreachable := ← jBool o "unreachable" }
    if !z.supported then return "unsupported"
    return verdictName (evaluate z op)
  | "check" =>
    let p ← zoneAt zs c "parent"
    let ch ← zoneAt zs c "child"
    if !(p.supported && ch.supported) then return "unsupported"
    let b ← c.getObjVal? "bounds"
    let llmRemaining ← match b.getObjVal? "llm_remaining" with
      | .ok (.arr #[r, t]) => pure (some (← r.getNat?, ← t.getNat?))
      | _ => pure none
    let bounds : Bounds := { zone := p, imagesOk := ← jBool b "images_ok", llmRemaining,
                             llmInputRemaining := ← jOptNat b "llm_input_remaining",
                             timeRemaining := ← jNat b "time_remaining_ms", childSlots := ← jNat b "child_slots" }
    return toString (check { zone := ch, maxChildren := ← jNat c "max_children" } bounds)
  | "reach_within" =>
    let o ← zoneAt zs c "outer"
    let i ← zoneAt zs c "inner"
    if !(o.supported && i.supported) then return "unsupported"
    return toString (reachWithin o i)
  | "host" => return toString (hostMatches (← jStr c "pattern") (← jStr c "host"))
  | "canon" =>
    match canonicalPath (← jStr c "path") with
    | some p => return (Json.str (stringOf p)).compress
    | none => return "null"
  | k => throw s!"unknown case kind {k}"

def main (args : List String) : IO UInt32 := do
  let some file := args.head? | IO.eprintln "usage: lean --run Oracle.lean cases.json"; return 2
  let input ← IO.FS.readFile file
  let j ← IO.ofExcept (Json.parse input)
  let zs ← IO.ofExcept ((← IO.ofExcept (jArr j "zones")).mapM parseZone)
  let zs := zs.toArray
  let cases ← IO.ofExcept (jArr j "cases")
  let out ← IO.getStdout
  for c in cases do
    match decideCase zs c with
    | .ok r => out.putStrLn r
    | .error e => out.putStrLn s!"error: {e}"
  out.flush
  return 0
