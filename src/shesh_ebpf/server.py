"""MCP server — eBPF telemetry with Aya (Rust) read-only stub (Python /proc fallback)."""

from __future__ import annotations

import pathlib
import time

try:
    from shesh_audit.guard import GuardedMCP as FastMCP
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        # Dummy fallback for testing without mcp installed
        class FastMCP:
            def __init__(self, name): self.name = name
            def tool(self):
                def decorator(fn):
                    return fn
                return decorator
            def run(self, transport="stdio"):
                print(f"{self.name} stub run")

mcp = FastMCP("shesh-ebpf")

def _read_proc(path: str) -> str:
    try:
        return pathlib.Path(path).read_text()
    except Exception:
        return ""

@mcp.tool()
def get_system_metrics() -> dict:
    """Get system metrics via /proc — Aya eBPF would provide richer, here read-only /proc fallback."""
    load = _read_proc("/proc/loadavg").split()[:3]
    meminfo = {}
    for line in _read_proc("/proc/meminfo").splitlines()[:10]:
        if ":" in line:
            k, v = line.split(":", 1)
            meminfo[k.strip()] = v.strip()
    uptime = _read_proc("/proc/uptime").split()[0] if _read_proc("/proc/uptime") else "0"
    return {
        "load_avg": load,
        "meminfo": meminfo,
        "uptime_seconds": uptime,
        "timestamp": time.time(),
        "source": "procfs (Aya eBPF stub — future Rust Aya would use BPF_MAP_TYPE_HASH for execve/openat)",
        "ebpf_available": False,
        "note": "Read-only, no kprobes modifying, behind Guard",
    }

@mcp.tool()
def get_network_stats() -> dict:
    net_dev = _read_proc("/proc/net/dev").splitlines()[:20]
    tcp = _read_proc("/proc/net/snmp").splitlines()[:20]
    return {
        "net_dev": net_dev,
        "tcp_snmp": tcp,
        "source": "procfs",
        "ebpf_future": "Aya would trace tcp_retransmit_skb via kprobe",
    }

@mcp.tool()
def get_process_io(pid: int = 1) -> dict:
    io_text = _read_proc(f"/proc/{pid}/io")
    if not io_text:
        return {"ok": False, "error": f"No /proc/{pid}/io", "stub": True}
    data = {}
    for line in io_text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return {"ok": True, "pid": pid, "io": data, "source": "procfs"}

@mcp.tool()
def list_ebpf_programs() -> dict:
    return {
        "programs": [
            {"name": "execve-tracer", "type": "kprobe", "status": "planned", "desc": "Trace execve via Aya BPF_PROG_TYPE_KPROBE"},
            {"name": "openat-tracer", "type": "kprobe", "status": "planned", "desc": "Trace openat for file access via Aya"},
            {"name": "tcp-retransmit", "type": "kprobe", "status": "planned", "desc": "Trace tcp_retransmit_skb via Aya"},
        ],
        "rust_crate": "ebpf-rs",
        "note": "Read-only, no modifications, behind Guard allow/confirm/deny",
    }

def main() -> None:
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
