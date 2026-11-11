#!/bin/sh
# What wicket-entry --hook would do, as gVisor's save/restore hook (installed into the experiment's
# rootfs only). gVisor runs it in the sandbox with GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE=save|resume|restore.
# On restore, put wicket.internal's address back on lo: the restore drops it, and the forwarders
# listen on it.
echo "hook mode=${GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE:-?} uid=$(id -u)" >> /tmp/hib-hook.log
case "${GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE:-}" in
  restore|resume) ip addr add 198.18.0.1/32 dev lo 2>>/tmp/hib-hook.log || true ;;
esac
exit 0
