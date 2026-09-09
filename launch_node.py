#!/usr/bin/env python3
"""Cross-platform supervised launcher for isolated KryptDisk nodes."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import shlex
import sys
import time
import re
import unicodedata
from typing import Dict, List, Optional, TextIO

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "mesh_config.json"
CORE_PATH = ROOT / "kdk_core.py"
RESTART_EXIT_CODES = {42, 43}
STARTUP_TIMEOUT_SECS = 20.0
STOP_TIMEOUT_SECS = 5.0


def _status(message: str) -> None:
    """Emit one stable preflight/status line for consoles and future splash adapters."""
    print(f"[LAUNCHER] {message}", flush=True)


class _InstanceLock:
    """Cross-platform, per-node exclusive lock held for the launcher lifetime."""

    def __init__(self, path: Path):
        self.path = path
        self.handle: Optional[TextIO] = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+", encoding="utf-8")
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                # Lock one byte without waiting. Ensure that byte exists first.
                if not handle.read(1):
                    handle.seek(0)
                    handle.write("0")
                    handle.flush()
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise RuntimeError("another launcher already owns this node") from exc
            else:
                import fcntl
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise RuntimeError("another launcher already owns this node") from exc
            handle.seek(0)
            handle.truncate()
            handle.write(str(os.getpid()))
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
            self.handle = handle
        except Exception:
            handle.close()
            raise

    def release(self) -> None:
        handle = self.handle
        self.handle = None
        if handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            handle.close()
        except Exception:
            pass


def _split_command(cmd: str) -> List[str]:
    try:
        return shlex.split(str(cmd or ""), posix=(os.name != "nt"))
    except Exception:
        return str(cmd or "").split()


def _has_option(parts: List[str], option: str, value: str) -> bool:
    option_l = option.lower()
    value_l = str(value).lower()
    for i, part in enumerate(parts):
        p = str(part).strip().strip('"').lower()
        if p == option_l and i + 1 < len(parts):
            return str(parts[i + 1]).strip().strip('"').lower() == value_l
        if p.startswith(option_l + "="):
            return p.split("=", 1)[1].strip().strip('"') == value_l
    return False


def _resolve_python_runtime() -> str:
    """Resolve the interpreter used for the updateable kdk_core.py child."""
    if not bool(getattr(sys, "frozen", False)):
        return os.path.abspath(sys.executable)

    candidates = []
    configured = str(os.environ.get("KDK_PYTHON", "") or "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.extend([
        ROOT / "runtime" / "python.exe",
        ROOT / "python" / "python.exe",
        ROOT / "python.exe",
    ])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    raise SystemExit(
        "[LAUNCHER] packaged launcher cannot find its private Python runtime; "
        "expected runtime\\python.exe (or set KDK_PYTHON)"
    )


def _atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_launcher_config(path: Path) -> dict:
    """Load the launcher configuration with errors suitable for a splash UI."""
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise SystemExit(f"[LAUNCHER] cannot read configuration {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"[LAUNCHER] configuration is not valid JSON: {path} "
            f"(line {exc.lineno}, column {exc.colno}: {exc.msg})"
        ) from exc
    if not isinstance(data, dict):
        raise SystemExit(f"[LAUNCHER] configuration root must be a JSON object: {path}")
    return data


def _config_port(value, *, label: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"[LAUNCHER] invalid {label} port={value!r}; expected 1..65535") from exc
    if port < 1 or port > 65535:
        raise SystemExit(f"[LAUNCHER] invalid {label} port={port}; expected 1..65535")
    return port


def _config_peer(value, *, label: str) -> str:
    peer = str(value or "").strip()
    if not peer or ":" not in peer:
        raise SystemExit(f"[LAUNCHER] invalid {label} peer={value!r}; expected host:port")
    host, port_raw = peer.rsplit(":", 1)
    if not host.strip():
        raise SystemExit(f"[LAUNCHER] invalid {label} peer={value!r}; host is empty")
    port = _config_port(port_raw, label=label)
    return f"{host.strip()}:{port}"


def _config_display_name(value, *, label: str) -> str:
    name = unicodedata.normalize("NFC", str(value or "")).strip()
    if not name:
        raise SystemExit(f"[LAUNCHER] {label} display name cannot be blank")
    if len(name) > 32:
        raise SystemExit(f"[LAUNCHER] {label} display name is too long; maximum is 32 characters")
    if any(unicodedata.category(ch).startswith("C") for ch in name):
        raise SystemExit(f"[LAUNCHER] {label} display name contains a control character")
    return name


def _load_profile_display_name(path: Path, fallback: str) -> str:
    """Return the persisted display name without coupling identity to its text."""
    if not path.exists():
        return _config_display_name(fallback, label="configured")
    try:
        raw = path.read_text(encoding="utf-8-sig")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[LAUNCHER] display-name profile is unreadable: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"[LAUNCHER] display-name profile must be a JSON object: {path}")
    return _config_display_name(data.get("display_name"), label="saved")


def _is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "")))


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except (OSError, ValueError):
        return False


def _ready_diagnostics(ready: dict, *, token: str, child_pid: int,
                       launcher_pid: int, node: str, port: int) -> dict:
    """Return explicit readiness comparison results for diagnostic output."""
    actual = {
        "token": str(ready.get("token", "") or ""),
        "pid": int(ready.get("pid", 0) or 0),
        "launcher_pid": int(ready.get("launcher_pid", 0) or 0),
        "name": str(ready.get("name", "") or ""),
        "port": int(ready.get("port", 0) or 0),
        "ppid": int(ready.get("ppid", 0) or 0),
        "ppid_verified": bool(ready.get("ppid_verified", False)),
    }
    expected = {
        "token": str(token),
        "pid": int(child_pid),
        "launcher_pid": int(launcher_pid),
        "name": str(node),
        "port": int(port),
    }
    checks = {
        "token": actual["token"] == expected["token"],
        # Some Windows Python launchers create an intermediate process. Accept
        # either the exact Popen PID or a core whose direct parent is that PID.
        "process_chain": (
            actual["pid"] == expected["pid"]
            or actual["ppid"] == expected["pid"]
        ),
        "launcher_pid": actual["launcher_pid"] == expected["launcher_pid"],
        "name": actual["name"] == expected["name"],
        "port": actual["port"] == expected["port"],
    }
    return {"actual": actual, "expected": expected, "checks": checks}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _process_snapshot() -> List[dict]:
    """Return pid/ppid/command records using built-in OS facilities."""
    if os.name == "nt":
        script = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress"
        )
        try:
            cp = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=12, check=True,
            )
            raw = json.loads(cp.stdout or "[]")
            if isinstance(raw, dict):
                raw = [raw]
            return [
                {
                    "pid": int(x.get("ProcessId", 0) or 0),
                    "ppid": int(x.get("ParentProcessId", 0) or 0),
                    "cmd": str(x.get("CommandLine", "") or ""),
                }
                for x in raw if isinstance(x, dict)
            ]
        except Exception:
            return []
    try:
        cp = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,args="], capture_output=True,
            text=True, timeout=8, check=True,
        )
        out = []
        for line in cp.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                out.append({"pid": int(parts[0]), "ppid": int(parts[1]), "cmd": parts[2]})
        return out
    except Exception:
        return []


def _normal(s: str) -> str:
    return os.path.normcase(os.path.abspath(s)).replace("\\", "/")


def _is_node_command(cmd: str, node: str, port: int, *,
                     profile_path: Optional[Path] = None,
                     display_name: str = "") -> bool:
    """Identify one core by stable profile/port, with legacy name fallback."""
    low = str(cmd or "").lower().replace("\\", "/")
    core = _normal(str(CORE_PATH)).lower()
    parts = _split_command(cmd)
    profile_ok = False
    if profile_path is not None:
        expected_profile = _normal(str(profile_path)).lower()
        for i, part in enumerate(parts):
            option = str(part).strip().strip('"').lower()
            if option == "--profile-path" and i + 1 < len(parts):
                profile_ok = _normal(str(parts[i + 1]).strip().strip('"')).lower() == expected_profile
                break
            if option.startswith("--profile-path="):
                raw_profile = str(part).split("=", 1)[1].strip().strip('"')
                profile_ok = _normal(raw_profile).lower() == expected_profile
                break
    name_ok = _has_option(parts, "--name", node)
    if display_name:
        name_ok = name_ok or _has_option(parts, "--name", display_name)
    return (
        (core in low or "/kdk_core.py" in low)
        and _has_option(parts, "--port", str(int(port)))
        and (profile_ok or name_ok)
    )


def _is_launcher_command(cmd: str, node: str) -> bool:
    low = str(cmd or "").lower().replace("\\", "/")
    parts = _split_command(cmd)
    launcher_named = (
        "/launch_node.py" in low
        or "kryptdisk launcher.exe" in low
        or "/kryptdisk-launcher" in low
    )
    return launcher_named and any(str(x).strip().strip('"').lower() == node.lower() for x in parts)


def _process_has_interactive_tty(pid: int) -> bool:
    """Best-effort test for whether an existing launcher still owns a live terminal."""
    if pid <= 0 or not _pid_alive(pid):
        return False
    if os.name == "nt":
        # A reliable cross-session console-attachment probe is not available here.
        # Be conservative on Windows: never auto-offer takeover of a live launcher.
        return True
    try:
        target = os.readlink(f"/proc/{int(pid)}/fd/0")
        return target.startswith("/dev/pts/") or target.startswith("/dev/tty")
    except Exception:
        pass
    try:
        cp = subprocess.run(
            ["ps", "-p", str(int(pid)), "-o", "tty="],
            capture_output=True, text=True, timeout=3, check=True,
        )
        tty = (cp.stdout or "").strip()
        return bool(tty and tty not in ("?", "-"))
    except Exception:
        return False


def _verified_launcher_pid(node: str, launcher_path: Path) -> int:
    """Return the recorded live launcher PID only if its command matches this node."""
    rec = _read_json(launcher_path)
    pid = int(rec.get("pid", 0) or 0)
    if pid <= 0 or pid == os.getpid() or not _pid_alive(pid):
        return 0
    for proc in _process_snapshot():
        if int(proc.get("pid", 0) or 0) == pid and _is_launcher_command(str(proc.get("cmd", "")), node):
            return pid
    return 0


def _offer_detached_takeover(node: str, launcher_path: Path) -> None:
    """Offer to replace a detached launcher so the TUI can move to this terminal."""
    pid = _verified_launcher_pid(node, launcher_path)
    if not pid:
        return
    if _process_has_interactive_tty(pid):
        raise SystemExit(
            f"[LAUNCHER] {node} is already running under launcher pid={pid}. "
            "Use its existing KryptDisk window; this duplicate launch will now close."
        )
    if not sys.stdin.isatty():
        raise SystemExit(
            f"[LAUNCHER] {node} is already running detached under launcher pid={pid}; "
            "interactive takeover requires a terminal"
        )

    print(f"[LAUNCHER] {node} is already running in a detached session.", flush=True)
    print("[LAUNCHER] Restarting will attach the TUI to this terminal and clear in-memory messages.", flush=True)
    try:
        answer = input("[LAUNCHER] Continue? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("y", "yes"):
        raise SystemExit(f"[LAUNCHER] leaving detached {node} running unchanged")

    _status(f"taking over detached {node} launcher pid={pid}")
    if not _terminate_verified(pid):
        raise SystemExit(f"[LAUNCHER] could not stop detached {node} launcher pid={pid}")

    # The launcher owns the per-node lock. Wait briefly for the OS to release it.
    deadline = time.time() + STOP_TIMEOUT_SECS
    while time.time() < deadline and _pid_alive(pid):
        time.sleep(0.10)


def _terminate_verified(pid: int) -> bool:
    print(f"[LAUNCHER] requesting graceful termination pid={pid}")
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T"], capture_output=True, timeout=8)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception as exc:
        print(f"[LAUNCHER] graceful termination warning pid={pid}: {exc}")

    deadline = time.time() + STOP_TIMEOUT_SECS
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.20)

    print(f"[LAUNCHER] forcing process termination pid={pid}")
    try:
        if os.name == "nt":
            cp = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid), "/T"],
                capture_output=True, text=True, timeout=8
            )
            # taskkill can report that the process has already disappeared; either
            # way, verify by polling rather than checking only 0.3 seconds later.
            if cp.returncode not in (0, 128):
                detail = (cp.stderr or cp.stdout or "").strip()
                if detail:
                    print(f"[LAUNCHER] forced termination note pid={pid}: {detail}")
        else:
            os.kill(pid, signal.SIGKILL)
    except Exception as exc:
        print(f"[LAUNCHER] forced termination warning pid={pid}: {exc}")

    deadline = time.time() + STOP_TIMEOUT_SECS
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.20)
    return not _pid_alive(pid)


def _guard_existing_node(node: str, port: int, launcher_path: Path, *,
                         profile_path: Optional[Path] = None,
                         display_name: str = "") -> None:
    snapshot = _process_snapshot()
    by_pid: Dict[int, dict] = {int(x["pid"]): x for x in snapshot}
    matches = [
        x for x in snapshot
        if int(x["pid"]) != os.getpid()
        and _is_node_command(
            x["cmd"], node, port,
            profile_path=profile_path,
            display_name=display_name,
        )
    ]
    for proc in matches:
        pid, ppid = int(proc["pid"]), int(proc["ppid"])
        parent = by_pid.get(ppid, {})
        if parent and _pid_alive(ppid) and _is_launcher_command(str(parent.get("cmd", "")), node):
            raise SystemExit(
                f"[LAUNCHER] {node} is already managed by launcher pid={ppid}, child pid={pid}; refusing duplicate start"
            )
        print(f"[LAUNCHER] stale {node} child detected pid={pid}; command and node identity verified")
        if not _terminate_verified(pid):
            raise SystemExit(f"[LAUNCHER] could not stop verified stale {node} child pid={pid}")
        print(f"[LAUNCHER] stale child stopped pid={pid}")



def _cleanup_matching_nodes(node: str, port: int, exclude_pid: int = 0, *,
                            profile_path: Optional[Path] = None,
                            display_name: str = "") -> bool:
    """Stop any remaining verified core for this exact node/port."""
    survivors = []
    for proc in _process_snapshot():
        pid = int(proc.get("pid", 0) or 0)
        if pid <= 0 or pid == exclude_pid or pid == os.getpid():
            continue
        if _is_node_command(
            str(proc.get("cmd", "")), node, port,
            profile_path=profile_path,
            display_name=display_name,
        ):
            _status(f"removing leftover {node} core pid={pid}")
            if not _terminate_verified(pid):
                survivors.append(pid)
    return not survivors

def _restore_backup(marker: dict, backup_root: Path) -> bool:
    try:
        target = Path(str(marker.get("target_path", ""))).resolve()
        backup = Path(str(marker.get("backup_path", ""))).resolve()
        expected = str(marker.get("previous_hash", ""))
        if target != CORE_PATH.resolve():
            return False
        if not _is_within(backup, backup_root):
            return False
        if not _is_sha256(expected):
            return False
        if not backup.is_file():
            return False
        raw = backup.read_bytes()
        import hashlib
        if hashlib.sha256(raw).hexdigest() != expected.lower():
            return False
        tmp = target.with_suffix(target.suffix + ".rollback.tmp")
        tmp.write_bytes(raw)
        if hashlib.sha256(tmp.read_bytes()).hexdigest() != expected.lower():
            try:
                tmp.unlink()
            except OSError:
                pass
            return False
        os.replace(tmp, target)
        return True
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch a supervised KryptDisk mesh node")
    parser.add_argument("node", help="Node name from mesh_config.json, e.g. Kryptonaut")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug-wire", action="store_true")
    args = parser.parse_args()

    _status("checking installation")
    if not CONFIG_PATH.is_file():
        raise SystemExit(f"[LAUNCHER] configuration missing: {CONFIG_PATH}")
    if not CORE_PATH.is_file():
        raise SystemExit(f"[LAUNCHER] core missing: {CORE_PATH}")
    cfg = _load_launcher_config(CONFIG_PATH)
    nodes = cfg.get("nodes", {})
    if not isinstance(nodes, dict) or not nodes:
        raise SystemExit(f"[LAUNCHER] configuration has no usable 'nodes' object: {CONFIG_PATH}")
    if args.node not in nodes:
        raise SystemExit(f"Unknown node {args.node!r}. Available: {', '.join(nodes)}")

    node_cfg = nodes[args.node]
    if not isinstance(node_cfg, dict):
        raise SystemExit(f"[LAUNCHER] configuration for node {args.node!r} must be a JSON object")
    port = _config_port(node_cfg.get("port"), label=f"node {args.node!r}")
    workdir = ROOT / "nodes" / args.node
    runtime = workdir / "runtime"
    ready_path = runtime / "node_ready.json"
    launcher_path = runtime / "launcher.json"
    profile_path = workdir / "profile.json"
    restart_marker = workdir / "updates" / "restart_pending.json"
    lock_path = runtime / "launcher.lock"
    workdir.mkdir(parents=True, exist_ok=True)
    runtime.mkdir(parents=True, exist_ok=True)

    configured_display_name = node_cfg.get("display_name", args.node)
    display_name = _load_profile_display_name(profile_path, configured_display_name)

    # A boot/systemd-started launcher may still be healthy but detached from any
    # terminal. Offer an explicit, destructive takeover before trying the lock:
    # restarting restores the TUI here, but in-memory messages are lost.
    _offer_detached_takeover(args.node, launcher_path)

    _status(f"acquiring exclusive node lock for {args.node}")
    instance_lock = _InstanceLock(lock_path)
    try:
        instance_lock.acquire()
    except RuntimeError as exc:
        raise SystemExit(f"[LAUNCHER] {args.node}: {exc}")

    _status("checking for existing processes")
    _guard_existing_node(
        args.node, port, launcher_path,
        profile_path=profile_path,
        display_name=display_name,
    )
    try:
        ready_path.unlink()
    except FileNotFoundError:
        pass

    _atomic_json(launcher_path, {"format": 1, "pid": os.getpid(), "node": args.node, "port": port, "started": int(time.time())})

    update_policy = str(cfg.get("update_policy", "stage") or "stage").strip().lower()
    if update_policy not in ("off", "manual", "stage", "force-latest"):
        raise SystemExit(
            f"[LAUNCHER] invalid update_policy={update_policy!r}; "
            "expected off, manual, stage or force-latest"
        )

    argv = [
        "--name", display_name,
        "--profile-path", str(profile_path.resolve()),
        "--port", str(port),
        "--no-default-peers",
        "--quiet-control",
        "--status-box",
        "--update-policy", update_policy,
    ]
    if bool(node_cfg.get("relay", True)):
        argv.append("--relay")
    if not bool(cfg.get("auto_apply_update", False)):
        argv.append("--no-auto-apply-capsules")
    if not bool(cfg.get("auto_restart_update", False)):
        argv.append("--no-auto-restart-update")
    if args.verbose:
        argv.append("--verbose")
    if args.debug_wire:
        argv.append("--debug-wire")

    # Apply one uniform PoW difficulty to every payload class on this node.
    # Real, dummy, receipt, chunk and HEIGHT-WAIT traffic therefore remain
    # indistinguishable by advertised PoW bits.
    pow_bits = int(node_cfg.get("pow_bits", cfg.get("pow_bits", 14)))
    if pow_bits < 0 or pow_bits > 30:
        raise SystemExit(f"[LAUNCHER] invalid pow_bits={pow_bits}; expected 0..30")
    argv += ["--pow-bits", str(pow_bits)]

    # Allow collision-earned turn frequency to be tuned per node for mesh
    # scaling experiments.  Per-node configuration overrides the global value.
    collision_trigger_n = int(
        node_cfg.get("collision_trigger_n", cfg.get("collision_trigger_n", 5))
    )
    if collision_trigger_n < 1:
        raise SystemExit(
            f"[LAUNCHER] invalid collision_trigger_n={collision_trigger_n}; expected >=1"
        )
    argv += ["--n", str(collision_trigger_n)]

    # Allow the stochastic relay fanout profile to be tuned from mesh_config.
    # Per-node configuration overrides the global value.  The core accepts a
    # comma-separated list such as: --fan-choices 1,1,1,1,2
    fan_choices = node_cfg.get("fan_choices", cfg.get("fan_choices"))
    if fan_choices is not None:
        if not isinstance(fan_choices, list) or not fan_choices:
            raise SystemExit(
                f"[LAUNCHER] invalid fan_choices={fan_choices!r}; expected a non-empty list of positive integers"
            )
        try:
            fan_values = [int(x) for x in fan_choices]
        except (TypeError, ValueError):
            raise SystemExit(
                f"[LAUNCHER] invalid fan_choices={fan_choices!r}; expected a non-empty list of positive integers"
            )
        if any(x < 1 for x in fan_values):
            raise SystemExit(
                f"[LAUNCHER] invalid fan_choices={fan_choices!r}; expected values >=1"
            )
        argv += ["--fan-choices", ",".join(str(x) for x in fan_values)]

    laptop = cfg.get("laptop")
    if isinstance(laptop, dict) and laptop.get("host") and laptop.get("port"):
        laptop_peer = f"{str(laptop['host']).strip()}:{_config_port(laptop['port'], label='legacy laptop')}"
        argv += ["--peer", laptop_peer]
    bootstrap_peers = cfg.get("bootstrap_peers", []) or []
    if not isinstance(bootstrap_peers, list):
        raise SystemExit("[LAUNCHER] bootstrap_peers must be a JSON list of host:port strings")
    for index, peer in enumerate(bootstrap_peers, start=1):
        argv += ["--peer", _config_peer(peer, label=f"bootstrap_peers[{index}]")]
    for other_name, other in nodes.items():
        if other_name != args.node:
            if not isinstance(other, dict):
                raise SystemExit(f"[LAUNCHER] configuration for node {other_name!r} must be a JSON object")
            other_port = _config_port(other.get("port"), label=f"node {other_name!r}")
            argv += ["--peer", f"127.0.0.1:{other_port}"]

    python_runtime = _resolve_python_runtime()
    # launch_node.py is the sole supervisor. Bypass kdk_core.py's own
    # compatibility supervisor and start the actual node process directly.
    command = [python_runtime, str(CORE_PATH), "--kdk-node-child", *argv]

    try:
        while True:
            token = secrets.token_hex(24)
            try:
                ready_path.unlink()
            except FileNotFoundError:
                pass
            env = os.environ.copy()
            env.update({
                "KDK_SUPERVISED": "1",
                "KDK_LAUNCHER_PID": str(os.getpid()),
                "KDK_LAUNCH_TOKEN": token,
                "KDK_READY_PATH": str(ready_path.resolve()),
            })
            print(f"[LAUNCHER] starting {args.node}: {command!r}")
            child = subprocess.Popen(command, cwd=workdir, env=env)

            deadline = time.time() + STARTUP_TIMEOUT_SECS
            confirmed = False
            last_ready = {}
            while time.time() < deadline:
                if child.poll() is not None:
                    break
                ready = _read_json(ready_path)
                if ready:
                    last_ready = ready
                ready_pid = int(ready.get("pid", 0) or 0)
                ready_ppid = int(ready.get("ppid", 0) or 0)
                process_chain_ok = (
                    ready_pid == child.pid
                    or ready_ppid == child.pid
                )
                if (
                    ready.get("token") == token
                    and process_chain_ok
                    and int(ready.get("launcher_pid", 0) or 0) == os.getpid()
                    # PPID is not used as general authentication. It is accepted
                    # only as proof of the specific one-generation Windows runtime
                    # chain: launcher -> Popen child -> kdk_core.
                    and ready.get("name") == display_name
                    and int(ready.get("port", 0) or 0) == port
                ):
                    confirmed = True
                    break
                time.sleep(0.20)

            if not confirmed:
                diag_ready = last_ready or _read_json(ready_path)
                diag = _ready_diagnostics(
                    diag_ready,
                    token=token,
                    child_pid=child.pid,
                    launcher_pid=os.getpid(),
                    node=display_name,
                    port=port,
                )

                print("[LAUNCHER] readiness diagnostics:", flush=True)
                if diag_ready:
                    print(json.dumps(diag_ready, indent=2, sort_keys=True), flush=True)
                else:
                    print("[LAUNCHER] no non-empty ready record was observed", flush=True)

                for key, ok in diag["checks"].items():
                    mark = "OK" if ok else "FAIL"
                    actual = diag["actual"].get(key)
                    expected = diag["expected"].get(key)
                    if key == "token":
                        actual = (str(actual)[:12] + "...") if actual else "<missing>"
                        expected = str(expected)[:12] + "..."
                    print(
                        f"[LAUNCHER] READY {mark:4} {key}: actual={actual!r} expected={expected!r}",
                        flush=True,
                    )

                failed_ready_path = runtime / "node_ready.failed.json"
                if diag_ready:
                    try:
                        _atomic_json(
                            failed_ready_path,
                            {
                                "captured_at": int(time.time()),
                                "ready": diag_ready,
                                "diagnostics": diag,
                            },
                        )
                        print(f"[LAUNCHER] preserved failed ready record: {failed_ready_path}", flush=True)
                    except Exception as exc:
                        print(f"[LAUNCHER] could not preserve failed ready record: {exc}", flush=True)

                _status(f"startup confirmation failed for child pid={child.pid}; cleaning up")
                if child.poll() is None and not _terminate_verified(child.pid):
                    raise SystemExit(
                        f"[LAUNCHER] {args.node} startup confirmation failed and child "
                        f"pid={child.pid} could not be terminated"
                    )
                if not _cleanup_matching_nodes(
                    args.node, port, exclude_pid=child.pid,
                    profile_path=profile_path,
                    display_name=display_name,
                ):
                    raise SystemExit(
                        f"[LAUNCHER] {args.node} startup confirmation failed and a verified core remained alive"
                    )
                marker = _read_json(restart_marker)
                if marker and _restore_backup(marker, workdir / "updates" / "backups"):
                    print("[LAUNCHER] promoted startup failed; previous build restored")
                    try:
                        restart_marker.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                raise SystemExit(f"[LAUNCHER] {args.node} startup ownership confirmation failed")

            ownership_mode = (
                "direct-child"
                if int(ready.get("pid", 0) or 0) == child.pid
                else "runtime-child"
            )
            print(
                f"[LAUNCHER] ownership confirmed launcher={os.getpid()} "
                f"popen_child={child.pid} core={int(ready.get('pid', 0) or 0)} "
                f"port={port} mode={ownership_mode} "
                f"ppid_verified={bool(ready.get('ppid_verified', False))}"
            )
            try:
                rc = int(child.wait())
            except KeyboardInterrupt:
                print("\n[LAUNCHER] interrupted; stopping child")
                _terminate_verified(child.pid)
                raise SystemExit(130)

            if rc in RESTART_EXIT_CODES:
                why = "update" if rc == 42 else "manual"
                print(f"[LAUNCHER] {why} restart requested; child exited cleanly, relaunching...")
                continue
            raise SystemExit(rc)
    finally:
        try:
            if int(_read_json(launcher_path).get("pid", 0) or 0) == os.getpid():
                launcher_path.unlink()
        except Exception:
            pass
        try:
            ready_path.unlink()
        except Exception:
            pass
        instance_lock.release()


if __name__ == "__main__":
    main()
