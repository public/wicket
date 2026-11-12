# The mock model's command: start the steps in the background (they wait for humans, longer than a
# Bash tool call may take) and end the turn.
nohup bash /workspace/steps.sh >/workspace/out/steps.out 2>&1 </dev/null &
echo started
