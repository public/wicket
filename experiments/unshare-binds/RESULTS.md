# Can `unshare -Urm` in a gVisor box strip its read-only binds? (#366)

wicket sets no seccomp profile of its own in a gVisor box, so a box can make a user namespace and
a mount namespace, and be root in them. The question: can that root then remount one of the box's
read-only binds read-write, unmount it, or bind it again read-write, and write through to the host?

**Verdict: no, on the gVisor tested.** `unshare -Urm` works (uid 0 in the namespace, no
capabilities outside it), but every way at a read-only bind fails, and so does every write:

| attempt | result |
|---|---|
| `mount -o remount,rw` and `remount,bind,rw` of `/wicket/ca`, `/` | `EPERM` |
| the same on a file bind (`/etc/hosts`) | refused (not a directory) |
| `umount2(/wicket/ca)`, `umount2(/etc/hosts)`, with and without `MNT_DETACH` | `EINVAL`: inherited mounts are locked |
| a new bind of `/wicket/ca`, then remounting it rw | `EPERM` on the bind |
| writing in `/wicket/ca`, to `/etc/hostname` | `EROFS`, `EACCES` |
| a new tmpfs on `/mnt` | allowed (a mount of its own, harmless) |

So a namespace's root can stack its own mounts in its own view, but can't change or remove the
box's. That is the kernel's rule for mounts inherited into a less privileged mount namespace
(`MNT_LOCKED`, and the read-only flag locked with it), and gVisor's sentry enforces it too.

**Method.** [`probe.sh`](probe.sh) and [`umount2.py`](umount2.py) (the `umount` binary checks its
mount table first, so `umount2` is also called directly) ran under `unshare -Urm` as the box's
unprivileged user (uid 996, no capabilities, `Seccomp: 0`). Raw output:
[`logs/2026-11-16-gvisor.txt`](logs/2026-11-16-gvisor.txt).

**Limits.**
- One gVisor build (kernel `4.19.0-gvisor`, inside a wicket worker box on 2026-11-16), not every one
  wicket supports.
- Not run under `isolation: runc`. There, Docker's default seccomp profile refuses `unshare` of a
  user namespace to an unprivileged process anyway, and Linux has the same locked-mount rule.
- It answers for the binds only. Nested namespaces still widen the sentry's syscall surface:
  setting a seccomp profile for gVisor boxes (no `CLONE_NEWUSER`) stays worth considering.
