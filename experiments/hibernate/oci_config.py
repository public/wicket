#!/usr/bin/env python3
"""Writes an OCI config.json for running the wicket agent box with runsc directly (no Docker), with
the same shape as box.sh: read-only root, /tmp tmpfs, the binds wicket makes, the capabilities
wicket-entry needs, no network (runsc --network=none), and Claude Code via wicket-entry.

    oci_config.py BUNDLE ROOT UID:GID -- CLAUDE_ARGS...   (BUNDLE/rootfs must exist)
"""
import json
import os
import sys

bundle, root, user = sys.argv[1], sys.argv[2], sys.argv[3]
extra = sys.argv[5:] if len(sys.argv) > 4 and sys.argv[4] == "--" else sys.argv[4:]
caps = ["CAP_NET_ADMIN", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"]
proxy = "http://wicket.internal:3128"
no_proxy = "localhost,127.0.0.1,::1,wicket.internal"
env = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "WICKET_AS_USER": user,
    "ANTHROPIC_BASE_URL": "http://wicket.internal:8080",
    "CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-wicket-placeholder-hib",
    "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
    "NO_PROXY": no_proxy, "no_proxy": no_proxy,
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1",
    "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CONFIG_DIR": "/wicket/state/claude", "HOME": "/wicket/state/home",
    "WICKET_RUN": "run_hib", "MCP_TOOL_TIMEOUT": "660000", "WICKET_TENANT": "default",
    "WICKET_CA_BUNDLE": "/tmp/ca-bundle.pem",
}
args = ["wicket-entry", "claude", "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
        "--permission-mode", "bypassPermissions", "--disallowedTools", "WebSearch",
        "--mcp-config", '{"mcpServers":{}}', "--strict-mcp-config"] + extra


def bind(src, dst, ro=False):
    return {"destination": dst, "type": "bind", "source": src, "options": ["rbind", "ro" if ro else "rw"]}


cfg = {
    "ociVersion": "1.0.0",
    "process": {
        "terminal": False,
        "user": {"uid": 0, "gid": 0},
        "args": args,
        "env": [f"{k}={v}" for k, v in env.items()],
        "cwd": "/workspace",
        "capabilities": {k: caps for k in ("bounding", "effective", "permitted")},
        "noNewPrivileges": True,
    },
    "root": {"path": "rootfs", "readonly": True},
    "hostname": "hib",
    "mounts": [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
        {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
        {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "size=512m"]},
        bind(f"{root}/hosts", "/etc/hosts", ro=True),
        bind(f"{root}/sock", "/wicket/sock"),
        bind(f"{root}/ca", "/wicket/ca", ro=True),
        bind(f"{root}/state", "/wicket/state"),
        bind(f"{root}/workspace", "/workspace"),
        bind(f"{root}/vol-cache", "/volumes/cache"),
    ],
    "linux": {
        "namespaces": [{"type": t} for t in ("pid", "ipc", "uts", "mount", "network")],
        "resources": {"memory": {"limit": 2 * 1024 ** 3}},
    },
}
with open(os.path.join(bundle, "config.json"), "w") as f:
    json.dump(cfg, f, indent=1)
