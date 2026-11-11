#!/usr/bin/env bash
# E4: hibernate by bundle, wake by rebuild + `claude --resume`.
# Needs session1.sh to have run (RUN_STATE = that run's state/ dir, VOL = its volume dir, WS = workspace).
#   RUN_STATE=... VOL=... WS=... WORK=/tmp/somewhere ./e4-resume.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${RUN_STATE:?}" "${VOL:?}" "${WS:?}" "${WORK:?}"
logs=$here/logs; mkdir -p "$logs"
now() { date +%s.%N; }
since() { echo "$(now) - $1" | bc; }
out=$logs/e4.txt; : > "$out"
say() { echo "$*" | tee -a "$out"; }

rm -rf "$WORK"; mkdir -p "$WORK"
store=$WORK/store
# The box stopped at a turn boundary; its trees are on the node's disk. Copy them, as a node would
# keep them until the push finishes.
r1=$WORK/r1; mkdir -p "$r1"
cp -a "$RUN_STATE" "$r1/state"; cp -a "$WS" "$r1/workspace"; cp -a "$VOL" "$r1/vol-cache"

say "== what Claude Code left in state/ (bytes, files)"
(cd "$r1/state" && for d in $(find . -mindepth 1 -maxdepth 2 | LC_ALL=C sort); do
  printf '%-40s %10s %5s\n' "$d" "$(du -sb "$d" | cut -f1)" "$(find "$d" -type f | wc -l)"; done) | tee -a "$out"
sid=$(basename "$(ls "$r1"/state/claude/projects/*/*.jsonl | head -1)" .jsonl)
say "session jsonl: $(wc -l < "$r1"/state/claude/projects/*/"$sid".jsonl) lines, $(stat -c %s "$r1"/state/claude/projects/*/"$sid".jsonl) bytes"

say "== push (hibernate): minimal bundle = projects/ + workspace + volume"
t0=$(now)
"$here/bundle.sh" push "$store" agent-hib 1 "$r1" state/claude/projects workspace vol-cache 2> "$WORK/push.t" >/dev/null
say "push total $(since "$t0") s"; tee -a "$out" < "$WORK/push.t"
say "store bytes $(du -sb "$store" | cut -f1)"
python3 - "$store/a/agent-hib/m/1" <<'PY' | tee -a "$out"
import json, sys
for t in json.load(open(sys.argv[1]))["trees"]:
    print(f"  {t['mount']:24} raw {t['raw']:>10}  stored {t['size']:>9}")
PY
say "== a second push of the same seq is refused (put-if-absent manifest)"
if "$here/bundle.sh" push "$store" agent-hib 1 "$r1" state/claude/projects 2>&1 | tail -1 | tee -a "$out"; then :; fi

# Wake: a fresh root on "another node": pull, unpack, verify, regenerate the rest.
wake_root() {
  local r=$1
  mkdir -p "$r/sock" "$r/ca" "$r/state/home" "$r/state/claude"
  cp "$WORK/ca.pem" "$r/ca/ca.pem"
  [ -d "$r/vol-cache" ] || mkdir -p "$r/vol-cache"; [ -d "$r/workspace" ] || mkdir -p "$r/workspace"
}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=hib-dummy-ca -days 2 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null

python3 "$here/mock_llm.py" --listen 127.0.0.1:9971 --log "$logs/e4-mock.jsonl" & mock=$!
socats=()
cleanup() { kill $mock "${socats[@]}" 2>/dev/null || true; ids=$(sudo -n docker ps -aq --filter label=hib=1); [ -z "$ids" ] || sudo -n docker rm -f $ids >/dev/null 2>&1 || true; }
trap cleanup EXIT
listen() { rm -f "$1/sock/llm.sock"; socat UNIX-LISTEN:"$1/sock/llm.sock",fork,mode=777 TCP:127.0.0.1:9971 & socats+=($!); for _ in $(seq 50); do [ -S "$1/sock/llm.sock" ] && break; sleep 0.05; done; }
msg() { python3 -c 'import json,sys; print(json.dumps({"type":"user","message":{"role":"user","content":[{"type":"text","text":sys.argv[1]}]}}))' "$1"; }

# wake NAME ROOT LOG MESSAGE -- CLAUDE_ARGS... : starts a box, sends one message, closes stdin.
wake() {
  local name=$1 r=$2 log=$3 text=$4; shift 4; [ "${1:-}" = -- ] && shift
  listen "$r"
  local t=$(now)
  { msg "$text"; sleep "${HOLD:-0}"; } | "$here/box.sh" "$name" "$r" -- "$@" 2>"$log.err" | T0=$t "$here/stamp.py" > "$log" || true
}
first() { awk -v p="$2" '$0 ~ p { print $1; exit }' "$1"; }

say "== wake 1: pull + unpack + verify, then rebuild and resume"
r2=$WORK/r2
t0=$(now)
"$here/bundle.sh" pull "$store" agent-hib 1 "$r2" 2> "$WORK/pull.t" | tee -a "$out"
say "pull total $(since "$t0") s"; tee -a "$out" < "$WORK/pull.t"
wake_root "$r2"
t1=$(now)
wake hib-wake1 "$r2" "$WORK/wake1.log" "HIB-WAKE you were asleep; what did you do before?" -- --resume "$sid"
say "box run total $(since "$t1") s; whole wake (pull..exit) $(since "$t0") s"
say "first stdout line (init)   at $(first "$WORK/wake1.log" '"type":"system"') s after docker run"
say "first assistant event      at $(first "$WORK/wake1.log" '"type":"assistant"') s"
say "result event               at $(first "$WORK/wake1.log" '"type":"result"') s"
grep -o 'RESUMED[^"]*' "$WORK/wake1.log" | head -1 | sed 's/^/agent said: /' | tee -a "$out"
grep -o '"session_id":"[^"]*"' "$WORK/wake1.log" | sort -u | sed "s/$sid/<the hibernated session>/" | sed 's/^/ids in output: /' | tee -a "$out"
say "workspace edit survived: $(grep -c 'edited' "$r2/workspace/notes/hibernate.md") edited lines; volume: $(wc -l < "$r2/vol-cache/seq.txt") lines"

say "== negative control: wake with the workspace but without projects/ (session lost)"
r3=$WORK/r3; mkdir -p "$r3"; cp -a "$r2/workspace" "$r3/"; cp -a "$r2/vol-cache" "$r3/"; wake_root "$r3"
wake hib-wake2 "$r3" "$WORK/wake2.log" "HIB-WAKE hello" -- --resume "$sid"
say "stdout: $(head -c 300 "$WORK/wake2.log" | tr '\n' ' ')"; say "stderr: $(tail -c 300 "$WORK/wake2.log.err" | tr '\n' ' ')"

say "== cwd matters: same bundle, workspace mounted at /work instead of /workspace"
r4=$WORK/r4; cp -a "$r2" "$r4"; rm -rf "$r4/sock"/*
WORKDIR=/work wake hib-cwd "$r4" "$WORK/cwd.log" "HIB-WAKE hello" -- --resume "$sid"
say "stdout: $(grep -o 'RESUMED[^"]*' "$WORK/cwd.log" | head -1)$(grep -o '"subtype":"error[^,]*' "$WORK/cwd.log" | head -1)"; say "stderr: $(tail -c 300 "$WORK/cwd.log.err" | tr '\n' ' ')"

say "project dirs after: $(ls "$r4/state/claude/projects" | tr '\n' ' '); jsonl files: $(cd "$r4/state/claude/projects" && ls -- */*.jsonl | sed 's/[0-9a-f-]\{36\}/<id>/' | tr '\n' ' ')"
say "== --fork-session: a new session id from the same transcript; the original is untouched"
r5=$WORK/r5; cp -a "$r2" "$r5"; rm -rf "$r5/sock"/*
before=$(sha256sum "$r5"/state/claude/projects/*/"$sid".jsonl | cut -c1-16)
wake hib-fork "$r5" "$WORK/fork.log" "HIB-WAKE forked" -- --resume "$sid" --fork-session
after=$(sha256sum "$r5"/state/claude/projects/*/"$sid".jsonl | cut -c1-16)
say "original jsonl unchanged: $([ "$before" = "$after" ] && echo yes || echo no); jsonl files now: $(ls "$r5"/state/claude/projects/*/*.jsonl | wc -l)"
grep -o 'RESUMED[^"]*' "$WORK/fork.log" | head -1 | sed 's/^/agent said: /' | tee -a "$out"

say "== cleanupPeriodDays: a 40-day-old transcript, then a new session kept open 30 s (the sweep is not immediate)"
for variant in default 3650; do
  r6=$WORK/r6-$variant; cp -a "$r2" "$r6"; rm -rf "$r6/sock"/*
  [ "$variant" = default ] || printf '{"cleanupPeriodDays": %s}\n' "$variant" > "$r6/state/claude/settings.json"
  touch -d '40 days ago' "$r6"/state/claude/projects/*/*.jsonl
  HOLD=30 wake "hib-clean${variant:0:1}" "$r6" "$WORK/clean-$variant.log" "HIB-WAKE fresh session" --
  say "cleanupPeriodDays=$variant: .last-cleanup $( [ -e "$r6/state/claude/.last-cleanup" ] && echo written || echo absent); old transcript $( [ -e "$r6/state/claude/projects/-workspace/$sid.jsonl" ] && echo kept || echo DELETED)"
done
say "== the same, but the wake resumes the old session itself (default settings)"
r7=$WORK/r7; cp -a "$r2" "$r7"; rm -rf "$r7/sock"/*
touch -d '40 days ago' "$r7"/state/claude/projects/*/*.jsonl
HOLD=30 wake hib-cleanr "$r7" "$WORK/clean-resume.log" "HIB-WAKE after 40 days" -- --resume "$sid"
say "resumed wake, default cleanupPeriodDays: answered $(grep -ac '"type":"result"' "$WORK/clean-resume.log") turn; transcript $( [ -e "$r7/state/claude/projects/-workspace/$sid.jsonl" ] && echo kept || echo DELETED)"
say "done"
# Session ids are random but still identifiers: keep them out of the committed log.
sed -i -E "s/$sid/<session>/g; s/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/<uuid>/g" "$out" "$logs/e4-mock.jsonl"
