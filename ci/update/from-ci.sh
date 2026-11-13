# Sourced by ci/update.sh: builds CI signed (#190), against a fake GitHub API on localhost. Each build
# is A with bytes appended, packaged by commit (ci/package.sh) and signed by build.yml's own `Sign`
# step (run here with a throwaway key: what the workflow does, byte for byte).
#   - --from-ci <commit>: an older build of main is taken; the audit names its commit and environment;
#   - refused: a branch's commit, a build whose claims name another ref, a hand-signed build (no
#     claims), and the token never reaches the artifact store;
#   - follow: the newest signed build of main is taken with no one's approval, then nothing (up to
#     date); a newer build still soaking is skipped, audited once however often it looks.

log "5b. builds CI signed: --from-ci, refusals, follow (a fake GitHub API)"
ci=$work/ci
mkdir -p "$ci"
openssl genpkey -algorithm ed25519 -out "$ci/key.pem" 2>/dev/null
openssl pkey -in "$ci/key.pem" -pubout -out "$ci/key.pub.pem"
w self trust-key "$ci/key.pub.pem" >/dev/null
sign_step=$(python3 -I -c 'import sys, yaml; w = yaml.safe_load(open(sys.argv[1])); print([s for s in w["jobs"]["sign"]["steps"] if s.get("name") == "Sign"][0]["run"])' .github/workflows/build.yml)
hex() { printf '%s' "$1" | sha256sum | cut -c1-40; }
# The fake API's state: main's history (oldest first), runs, and artifact files by id.
echo '{"main": [], "runs": [], "files": {}}' >"$ci/api.json"
api_add() { # label commit run_id archive sig: a run that published a signed build
  jq --arg c "$2" --argjson id "$3" --arg a "$4" --arg s "$5" \
    '.runs = [{id: $id, sha: $c, archive: ($a | split("/") | last), aid: ($id * 10), sid: ($id * 10 + 1)}] + .runs
     | .files[($id * 10 | tostring)] = $a | .files[($id * 10 + 1 | tostring)] = $s' "$ci/api.json" >"$ci/api.new" && mv "$ci/api.new" "$ci/api.json"
}
on_main() { jq --arg c "$1" '.main += [$c]' "$ci/api.json" >"$ci/api.new" && mv "$ci/api.new" "$ci/api.json"; }
build() { # label commit ref run_id: a signed build; prints "archive sig"
  local d=$ci/b-$1
  mkdir -p "$d/dist"
  cp "$A" "$d/w" && printf '\nwicket ci/update.sh CI build %s\n' "$1" >>"$d/w"
  local a; a=$(ci/package.sh "$d/w" "$d/dist" "${2:0:12}")
  (cd "$d" && KEY="$(cat "$ci/key.pem")" ARCHIVE=$(basename "$a") BUILT_SHA256=$(cut -d' ' -f1 "$a.sha256") REPO=acme/wicket \
    COMMIT=$2 REF=$3 WORKFLOW_REF="acme/wicket/.github/workflows/build.yml@$3" RUN_ID=$4 RUN_ATTEMPT=1 RUNNER_TEMP=$d bash -c "$sign_step" >/dev/null)
  echo "$a $a.sig"
}
port=$(free_port)
cat >"$ci/api.py" <<'EOF'
import http.server, json, sys
state, log = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body=b"", ctype="application/json", headers=()):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        for k, v in headers: self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        s = json.load(open(state))
        path, _, query = self.path.partition("?")
        with open(log, "a") as f:
            f.write("%s auth=%s\n" % (path, "yes" if self.headers.get("authorization", "") == "Bearer tok" else "no"))
        j = lambda v: self.send(200, json.dumps(v).encode())
        main = s["main"]
        p = path.split("/")
        if path.startswith("/repos/acme/wicket/actions/workflows/build.yml/runs"):
            want = dict(q.split("=", 1) for q in query.split("&") if "=" in q).get("head_sha")
            runs = [{"id": r["id"], "head_sha": r["sha"], "head_branch": "main", "event": "push", "path": ".github/workflows/build.yml"}
                    for r in s["runs"] if want in (None, r["sha"])]
            return j({"workflow_runs": runs})
        if path.startswith("/repos/acme/wicket/actions/runs/") and path.endswith("/artifacts"):
            r = [r for r in s["runs"] if str(r["id"]) == p[6]][0]
            return j({"artifacts": [{"id": r["aid"], "name": r["archive"], "expired": False},
                                    {"id": r["sid"], "name": r["archive"] + ".sig", "expired": False}]})
        if path.startswith("/repos/acme/wicket/compare/"):
            base, head = p[5].split("...")
            base = main[-1] if base == "main" else base
            if base in main and head in main:
                d = main.index(head) - main.index(base)
                return j({"status": "identical" if d == 0 else ("ahead" if d > 0 else "behind"), "ahead_by": max(d, 0), "behind_by": max(-d, 0)})
            return j({"status": "diverged", "ahead_by": 1, "behind_by": 1})
        if path.startswith("/repos/acme/wicket/commits/"):
            known = main + [r["sha"] for r in s["runs"]]
            full = [c for c in known if c.startswith(p[5])]
            return j({"sha": full[0]}) if full else self.send(404, b"{}")
        if path.startswith("/repos/acme/wicket/actions/artifacts/") and path.endswith("/zip"):
            return self.send(302, headers=[("location", "http://127.0.0.1:%d/store/%s" % (self.server.server_port, p[6]))])
        if path.startswith("/store/"):
            return self.send(200, open(s["files"][p[2]], "rb").read(), "application/octet-stream")
        self.send(404, b"{}")
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[3])), H).serve_forever()
EOF
python3 -I "$ci/api.py" "$ci/api.json" "$ci/api.log" "$port" &
pids+=($!)
printf 'tok' | w secret set github-ci-read --hosts api.github.com >/dev/null
printf 'repo: acme/wicket\ntoken_secret: github-ci-read\napi: http://127.0.0.1:%s\n' "$port" >"$WICKET_HOME/ci-builds.yaml"
wait_for 20 'curl -s "http://127.0.0.1:$port/" >/dev/null' || true

D=$(hex d) E=$(hex e) F=$(hex f) X=$(hex x) Y=$(hex y) Z=$(hex z)
on_main "$D"; on_main "$Y"; on_main "$Z"; on_main "$E"
read -r d_art d_sig < <(build d "$D" refs/heads/main 101)
api_add d "$D" 101 "$d_art" "$d_sig"
read -r e_art e_sig < <(build e "$E" refs/heads/main 102)
api_add e "$E" 102 "$e_art" "$e_sig"
read -r x_art x_sig < <(build x "$X" refs/heads/main 103)
api_add x "$X" 103 "$x_art" "$x_sig"   # a branch's commit: not on main
read -r y_art y_sig < <(build y "$Y" refs/heads/feature 104)
api_add y "$Y" 104 "$y_art" "$y_sig"   # claims another ref
# Z: signed by hand (`wicket self sign`, no claims) with the trusted release key.
cp "$A" "$ci/z" && printf '\nwicket ci/update.sh CI build z\n' >>"$ci/z"
z_art=$(ci/package.sh "$ci/z" "$ci/zd" "${Z:0:12}")
w self sign --key "$work/release.key" "$z_art" >/dev/null
api_add z "$Z" 105 "$z_art" "$z_art.sig"
D_ID=$(id_of "$ci/b-d/w") E_ID=$(id_of "$ci/b-e/w")

w self update --from-ci "${D:0:12}" --window 5s --interval 5s >"$work/u-ci-d.log" 2>&1
st=$?
W=$WICKET_HOME/versions/current/wicket
tail -3 "$work/u-ci-d.log"
check "--from-ci takes an older signed build of main by its commit" '[ "$st" = 0 ] && [ "$(current "$WICKET_HOME/versions")" = "$D_ID" ]'
check "  the audit names its commit, main and the release environment" \
  'w audit --tail 300 | grep self.staged | grep "\"commit\":\"$D\"" | grep "\"ref\":\"refs/heads/main\"" | grep -q "\"environment\":\"release\""'
check "  the token went to the API only, never to the artifact store" 'grep -q "^/store/.* auth=no" "$ci/api.log" && ! grep -q "^/store/.* auth=yes" "$ci/api.log" && ! grep -q "^/repos/.* auth=no" "$ci/api.log"'
check "a branch's commit is refused" '! w self update --from-ci "$X" >"$work/u-ci-x.log" 2>&1 && grep -q "is not on main" "$work/u-ci-x.log"'
check "a build whose claims name another ref is refused" '! w self update --from-ci "$Y" >"$work/u-ci-y.log" 2>&1 && grep -q "not refs/heads/main" "$work/u-ci-y.log"'
check "a hand-signed build (no claims) is refused for --from-ci" '! w self update --from-ci "$Z" >"$work/u-ci-z.log" 2>&1 && grep -q "no claims" "$work/u-ci-z.log"'
check "  and the control host still runs D" '[ "$(current "$WICKET_HOME/versions")" = "$D_ID" ]'

printf 'follow:\n  soak: 0s\n  gate_window: 5s\n' >>"$WICKET_HOME/ci-builds.yaml"
w self follow >"$work/follow-1.log" 2>&1
st=$?
tail -3 "$work/follow-1.log"
check "follow takes main's newest signed build (E), with no one's approval" '[ "$st" = 0 ] && [ "$(current "$WICKET_HOME/versions")" = "$E_ID" ] && w audit --tail 300 | grep self.follow_update | grep -q "\"to\":\"$E\""'
check "  then has nothing to do" 'w self follow 2>&1 | grep -q "up to date"'
on_main "$F"
read -r f_art f_sig < <(build f "$F" refs/heads/main 106)
api_add f "$F" 106 "$f_art" "$f_sig"
sed -i 's/soak: 0s/soak: 1h/' "$WICKET_HOME/ci-builds.yaml"
w self follow >"$work/follow-2.log" 2>&1
w self follow >>"$work/follow-2.log" 2>&1
check "a newer build still soaking is skipped, and audited once, however often it looks" \
  'grep -q "soaks for 1h" "$work/follow-2.log" && [ "$(w audit --tail 300 | grep self.follow_skipped | grep -c "$F")" = 1 ] && [ "$(current "$WICKET_HOME/versions")" = "$E_ID" ]'
