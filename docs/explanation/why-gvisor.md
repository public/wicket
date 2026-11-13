# Why gVisor

Every box runs under gVisor (`runsc`) unless its zone says `isolation: runc`, which is for
development only. This page explains the choice. The full discussion is design §7.2 and research
[02](research/02-isolation.md) and [10](research/10-infrastructure.md).

## What a box must not be able to do

wicket treats everything in the box as hostile, including the agent and its own settings. The box
holds no secrets and has no network, so its only ways out are wicket's proxies, over bind-mounted
unix sockets, and the boundary itself. The boundary is what stands between a compromised agent and
the host that holds the ledger, the keys and every other box.

## The tiers

From weakest to strongest boundary between a workload and its host:

| tier | examples | the boundary | needs |
|---|---|---|---|
| process sandbox | seccomp, namespaces and Landlock (bubblewrap, nsjail; Claude Code's own sandbox) | the host kernel, with calls restricted | nothing |
| container | `runc` | the host kernel, with namespaces and limits | nothing |
| user-space kernel | **gVisor** | a kernel in Go intercepts system calls; the host kernel sees a small fixed set | nothing special |
| microVM | Firecracker, Cloud Hypervisor, Kata | the workload's own kernel behind hardware virtualization | KVM |

A process sandbox or a container leaves the whole host kernel as attack surface. A microVM is
stronger, but needs KVM, which most cheap cloud VMs (Vultr, Hetzner Cloud) don't expose; only bare
metal or the few instance types with nested virtualization do, at higher cost. It also needs its own
kernel and root filesystem per box, which costs memory and machinery.

gVisor is the strongest boundary that runs on any VPS. That is why it is the default, and the floor:
the subset rule ranks `runc < gvisor < vm`, so a child can never get weaker isolation than its
parent.

## What it costs

- **UDP is expensive.** gVisor spends about 110 µs of CPU per UDP datagram, so HTTP/3 in a box runs
  at 40–100 Mbit/s with standard packets ([use HTTP/3](../how-to/use-http3.md)). TCP through the
  in-box forwarder runs at 170–350 MB/s ([performance](performance.md)).
- **A socket the box creates can't be reached from the host**, though the box can connect out to a
  host socket. So wicket reaches into a box for each link connection with `docker exec`, which costs
  140–200 ms per new connection.
- **`--host-uds=open`** must be set on the runtime: boxes reach wicket only through unix sockets.

## What it doesn't give

gVisor is a user-space kernel, not a VM: a bug in it, or in the host kernel's small exposed surface,
is still an escape. MicroVM isolation (Firecracker on hosts with KVM, #64) is designed but not built
in 0.0.1. And Docker, which starts the boxes, is root on the host: only the `wicket` user may use it
([security model](security-model.md)).
