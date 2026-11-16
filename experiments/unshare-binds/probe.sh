#!/bin/bash
# #366 experiment: can a user+mount namespace inside a gVisor box strip its read-only binds?
echo "uid in ns: $(id -u)"
for m in /wicket/ca /etc/hosts /; do
  printf '%-12s remount,rw: ' "$m"; mount -o remount,rw "$m" 2>&1 && echo OK || true
  printf '%-12s remount,bind,rw: ' "$m"; mount -o remount,bind,rw "$m" 2>&1 && echo OK || true
done
printf 'umount /etc/hosts: '; umount /etc/hosts 2>&1 && echo OK || true
printf 'umount -l /wicket/ca: '; umount -l /wicket/ca 2>&1 && echo "OK (now: $(ls /wicket/ca 2>&1 | head -3 | tr '\n' ' '))" || true
printf 'write /wicket/ca: '; (touch /wicket/ca/.wicket-exp && echo WROTE && rm -f /wicket/ca/.wicket-exp) 2>&1
printf 'write /etc/hostname: '; (echo x >> /etc/hostname && echo WROTE) 2>&1
printf 'mount tmpfs: '; mount -t tmpfs none /mnt 2>&1 && echo OK || true
printf 'new bind rw of /wicket/ca: '; mkdir -p /tmp/expb && mount --bind /wicket/ca /tmp/expb 2>&1 && { mount -o remount,bind,rw /tmp/expb 2>&1 && echo "remounted rw" || true; touch /tmp/expb/.x 2>&1 && echo WROTE && rm -f /tmp/expb/.x; } || true
grep -E " /wicket/ca | /etc/hosts " /proc/self/mounts
