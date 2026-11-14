# Hibernate and wake: write a file in each writable place on the first turn, report them later.
if [ -f /workspace/turn1 ]; then
  jq -n --arg tmp "$(cat /tmp/acc-tmp 2>/dev/null)" --arg home "$(cat "$HOME/acc-home" 2>/dev/null)" \
    --arg ws "$(cat /workspace/acc-ws 2>/dev/null)" --arg vol "$(cat /volumes/data/acc-vol 2>/dev/null)" \
    '{tmp:$tmp,home:$home,ws:$ws,vol:$vol,turn:"later"}' > /workspace/out/result.json
else
  echo tmp-kept > /tmp/acc-tmp; echo home-kept > "$HOME/acc-home"; echo ws-kept > /workspace/acc-ws
  echo vol-kept > /volumes/data/acc-vol; touch /workspace/turn1
  echo '{"turn":"first"}' > /workspace/out/result.json
fi
echo "wicket-mock: hibernate"
