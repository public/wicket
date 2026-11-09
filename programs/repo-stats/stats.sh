#!/bin/bash
# repo-stats: a deterministic program (the kind an agent might write once and reuse).
# Reads one GitHub repo's public stats and writes them to the outbox. No model involved.
set -euo pipefail
repo="${REPO:-octocat/Hello-World}"
json=$(curl -sf "https://api.github.com/repos/$repo")
echo "fetched $repo"
# Outside this program's approved reach: with on_pending: fail, this fails without asking anyone.
code=$(curl -s -o /dev/null -w '%{http_code}' https://example.com/ || true)
echo "example.com -> $code (expected 403: programs do not escalate)"
jq -n --argjson r "$json" --arg probe "$code" '{status:"done", repo:$r.full_name, stars:$r.stargazers_count, forks:$r.forks_count, open_issues:$r.open_issues_count, default_branch:$r.default_branch, pushed_at:$r.pushed_at, outside_reach_probe:$probe}' > /workspace/out/result.json
echo "wrote result.json"
