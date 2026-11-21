# The mock model's command: start the steps in the background (they wait for humans, longer than a
# Bash tool call may take) and end the turn, staying open.
# Once only: a later turn (wicket's notice that messages are waiting, which steps.sh reads itself)
# just stays open.
if [ -e /workspace/out/steps.started ]; then echo "steps already running"; echo "wicket-mock: stay"; exit 0; fi
: >/workspace/out/steps.started
nohup bash /workspace/steps.sh >/workspace/out/steps.out 2>&1 </dev/null &
echo started
echo "wicket-mock: stay"
