#!/bin/bash
# Question 6 (GSO): 8 MB POSTs from the box, the in-box client's UDP GSO on and off. gVisor accepts
# UDP_SEGMENT but doesn't segment (probe/run-q1.sh: udp-gso-send), so a GSO batch reaches the
# forwarder as one oversized datagram. Usage: scripts/upload.sh [term flags]. Appends logs/upload.log.
set -u
. "$(dirname "$0")/lib.sh"
start_host "$@"
{
echo "# $(date -u +%FT%TZ) runtime $RT term flags: $*"
box "
G='/opt/h3spike get --ca /wicket/ca/ca.pem --quiet --method POST --body 8000000 ${CLIENT_ARGS:-}'
echo '== GSO on'; timeout 60 \$G https://h3.test/allowed/up || echo \"exit \$?\"
echo '== GSO off'; timeout 60 \$G --no-gso https://h3.test/allowed/up || echo \"exit \$?\"
"
} 2>&1 | tee -a "$LOGS/upload.log"
