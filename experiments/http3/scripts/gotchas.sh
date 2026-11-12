#!/bin/bash
# Question 6: 0-RTT, migration, idle timeout, through the whole chain in a gVisor box.
# Usage: scripts/gotchas.sh default|no-migration|short-idle. Appends to logs/gotchas.log.
set -u
mode=${1:-default}
. "$(dirname "$0")/lib.sh"
case $mode in
  default) start_host ;;
  no-migration) start_host --no-migration ;;
  short-idle) start_host --idle 3 ;;
esac
out=$LOGS/gotchas.log
{
echo "# $(date -u +%FT%TZ) mode $mode runtime $RT"
box "
G='/opt/h3spike get --ca /wicket/ca/ca.pem'
case $mode in
default)
  echo '== 0-RTT: second connection offers early data'
  \$G --conns 2 --zero-rtt https://h3.test/allowed/z
  echo '== migration: client rebinds to a new port after the first request'
  \$G --n 3 --rebind-after 1 https://h3.test/allowed/m ;;
no-migration)
  echo '== migration refused by the terminator: client rebinds after the first request'
  \$G --n 3 --rebind-after 1 --idle 5 https://h3.test/allowed/m ;;
short-idle)
  echo '== idle: terminator idle timeout 3 s, client pauses 5 s between requests'
  \$G --n 3 --pause 5 https://h3.test/allowed/i ;;
esac
"
echo "== term log"; cat "$run/term.log"
echo "== audit"; cat "$run/audit.jsonl"
} 2>&1 | tee -a "$out"
