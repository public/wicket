// An example org policy (docs/policy.md). CI compiles it and, when it changes, asks SymCC
// whether the change narrows or widens (ci/policy-diff.sh).
// Every zone may do what its own policy says, within this (spawns are narrowed below).
permit(principal, action in [Action::"GET", Action::"HEAD", Action::"POST", Action::"PUT", Action::"PATCH",
  Action::"DELETE", Action::"OPTIONS", Action::"message", Action::"inject"], resource);

// Nobody deletes on production, and nothing reaches the metadata service.
forbid(principal, action in [Action::"DELETE"], resource) when { resource.host == "prod.example.com" };
forbid(principal, action in [Action::"GET", Action::"POST"], resource) when { resource.host == "metadata.google.internal" };

// Development zones never write to the main repository.
forbid(principal in Group::"dev", action in [Action::"PUT", Action::"POST", Action::"PATCH", Action::"DELETE"], resource)
  when { resource.host == "api.github.com" && resource.path_matches.contains("/repos/acme/main/**") };

// Children spawned by agents stay on gVisor and under 2 GiB.
permit(principal, action == Action::"spawn", resource) when { context.isolation >= 2 && context.memory <= 2147483648 };
