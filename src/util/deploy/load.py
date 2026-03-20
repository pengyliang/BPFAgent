from __future__ import annotations

import os
import re
import subprocess
import time
import json
import signal
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from src.util.deploy.commands import run_command
from src.util.deploy.verifier import parse_verifier_log


def _force_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def extract_phase_json(stdout_text: Any) -> Dict[str, Dict[str, Any]]:
    phases: Dict[str, Dict[str, Any]] = {}
    raw = str(stdout_text or "")
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("PHASE_JSON "):
            continue
        payload = line[len("PHASE_JSON ") :].strip()
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        phase = str(obj.get("phase") or "")
        if phase:
            phases[phase] = obj
    return phases


def terminate_loader_daemon(proc: Any, *, timeout: float = 5.0) -> bool:
    if not proc:
        return True
    try:
        if proc.poll() is not None:
            return True
    except Exception:
        return False

    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        pgid = None

    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=timeout)
        return True
    except Exception:
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
            proc.wait(timeout=timeout)
            return True
        except Exception:
            return False


def terminate_loader_daemon_by_pin_path(pin_path: str, *, timeout: float = 5.0) -> bool:
    _, loader_bin = _libbpf_loader_paths()
    target = f"--pin-path {pin_path}"

    def _matching_pids() -> list[str]:
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid=,args="],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception:
            return []

        pids: list[str] = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            pid, args = parts
            if str(loader_bin) in args and target in args:
                pids.append(pid)
        return pids

    pids = _matching_pids()
    if not pids:
        return True

    run_command(["sudo", "kill", "-TERM", *pids], timeout=max(1, int(timeout)))
    time.sleep(min(timeout, 1.0))
    remaining = _matching_pids()
    if not remaining:
        return True

    run_command(["sudo", "kill", "-KILL", *remaining], timeout=max(1, int(timeout)))
    time.sleep(0.2)
    return not _matching_pids()


def safe_unpin(pin_path: str) -> bool:
    path = Path(pin_path)
    try:
        if path.exists() or path.is_symlink():
            path.unlink()
            return True
    except OSError:
        pass

    result = run_command(["sudo", "rm", "-f", str(path)], timeout=10)
    return result["returncode"] == 0 and not result["timed_out"]


def safe_remove_tree(path_value: str) -> bool:
    result = run_command(["sudo", "rm", "-rf", str(path_value)], timeout=10)
    return result["returncode"] == 0 and not result["timed_out"]


def safe_unpin_links_flat(pin_path: str) -> bool:
    """Remove all link pins created by loader: pin_path_link_NN_name (flat under bpffs)."""
    pin = Path(pin_path)
    prefix = pin.name + "_link_"
    parent = pin.parent
    try:
        if not parent.exists():
            return True
        for child in parent.iterdir():
            if child.is_file() and child.name.startswith(prefix):
                safe_unpin(str(child))
        return True
    except OSError:
        pass
    result = run_command(["sudo", "bash", "-c", f"rm -f {parent / (prefix + '*')}"], timeout=10)
    return result["returncode"] == 0 and not result["timed_out"]


def _libbpf_loader_paths() -> Tuple[Path, Path]:
    loader_dir = Path(__file__).resolve().parents[2] / "ebpf" / "utils"
    loader_bin = loader_dir / "loader"
    return loader_dir, loader_bin


def _build_libbpf_loader(*, timeout: int = 60) -> Dict[str, Any]:
    loader_dir, loader_bin = _libbpf_loader_paths()
    if loader_bin.exists():
        return {
            "success": True,
            "loader_bin": str(loader_bin),
            "command": ["make", "-C", str(loader_dir)],
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "timed_out": False,
        }

    build_result = run_command(["make", "-C", str(loader_dir)], timeout=timeout)
    success = build_result["returncode"] == 0 and not build_result["timed_out"] and loader_bin.exists()
    return {
        "success": success,
        "loader_bin": str(loader_bin),
        "command": build_result["command"],
        "stdout": build_result["stdout"],
        "stderr": build_result["stderr"],
        "returncode": build_result["returncode"],
        "timed_out": build_result["timed_out"],
    }


def start_libbpf_loader_daemon(*, object_file: str, pin_path: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Start loader as a long-running process that loads+attaches with libbpf and pins maps.
    Attach lifetime is bound to the loader process lifetime.
    """
    _, loader_bin = _libbpf_loader_paths()
    cmd = ["sudo", str(loader_bin), "--obj", str(object_file), "--pin-path", str(pin_path)]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )

    deadline = time.time() + float(timeout)
    ready_line = None
    stderr_acc = []
    stdout_acc = []
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            line = proc.stdout.readline() if proc.stdout else ""
        except Exception:
            line = ""
        if line:
            stdout_acc.append(line)
            if line.startswith("READY "):
                ready_line = line.strip()
                break
        else:
            time.sleep(0.05)
    if not ready_line:
        # Drain remaining output for better diagnostics.
        try:
            out_rest = ""
            err_rest = ""
            try:
                out_rest, err_rest = proc.communicate(timeout=0.2)
            except Exception:
                if proc.stderr:
                    err_rest = proc.stderr.read() or ""
                if proc.stdout:
                    out_rest = proc.stdout.read() or ""
            if out_rest:
                stdout_acc.append(out_rest)
            if err_rest:
                stderr_acc.append(err_rest)
        except Exception:
            pass
        stdout_text = "".join(stdout_acc).strip()
        stderr_text = "".join(stderr_acc).strip()
        returncode = proc.poll()
        phase_details = extract_phase_json(stdout_text)
        load_phase = phase_details.get("load") if isinstance(phase_details.get("load"), dict) else None
        attach_phase = phase_details.get("attach") if isinstance(phase_details.get("attach"), dict) else None
        load_success = bool(load_phase.get("ok")) if load_phase else returncode in (0, 20)
        attach_success = bool(attach_phase.get("ok")) if attach_phase else False
        failed_stage = "attach" if returncode == 20 or (attach_phase and not attach_success) else "load"
        error_message = "loader did not become READY"
        if failed_stage == "attach":
            error_message = (
                str((attach_phase or {}).get("error_message") or (attach_phase or {}).get("stderr") or "").strip()
                or stderr_text
                or error_message
            )
        elif load_phase and not load_success:
            error_message = (
                str((load_phase or {}).get("error_message") or (load_phase or {}).get("stderr") or "").strip()
                or stderr_text
                or error_message
            )

        return {
            "success": False,
            "stage": failed_stage,
            "via_libbpf_loader_daemon": True,
            "command": cmd,
            "pid": proc.pid,
            "ready_line": None,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "returncode": returncode,
            "error_message": error_message,
            "load_success": load_success,
            "attach_success": attach_success,
            "phase_details": phase_details,
            "_process": proc,
        }

    m = re.search(r"\bmaps_dir=([^\s]+)", ready_line)
    maps_dir = m.group(1) if m else None
    return {
        "success": True,
        "stage": "load",
        "via_libbpf_loader_daemon": True,
        "command": cmd,
        "pid": proc.pid,
        "ready_line": ready_line,
        "maps_dir": maps_dir,
        "_process": proc,
    }


def load_bpf_program_bpftool(
    *,
    object_file: str,
    pin_path: str,
    bpftool_bin: str = "bpftool",
    program_type: Optional[str] = None,
    autoattach: bool = False,
    timeout: int = 60,
    cleanup_on_failure: bool = True,
    cleanup_existing_pin: bool = True,
) -> Dict[str, Any]:
    pin = Path(pin_path)
    pin.parent.mkdir(parents=True, exist_ok=True)

    pre_unpinned_existing = False
    if cleanup_existing_pin:
        pre_unpinned_existing = safe_unpin(str(pin))

    cmd = ["sudo", bpftool_bin, "-d", "prog", "load", str(object_file), str(pin)]
    if program_type:
        cmd.extend(["type", program_type])
    if autoattach:
        cmd.append("autoattach")

    result = run_command(cmd, timeout=timeout)
    combined_log = (result["stdout"] or "") + "\n" + (result["stderr"] or "")

    success = result["returncode"] == 0 and not result["timed_out"]
    verifier = parse_verifier_log(combined_log if not success else "")

    unpinned = False
    if not success and cleanup_on_failure:
        unpinned = safe_unpin(str(pin))

    return {
        "success": success,
        "stage": "load",
        "object_file": str(object_file),
        "pin_path": str(pin),
        "autoattach": autoattach,
        "pre_unpinned_existing": pre_unpinned_existing,
        "command": cmd,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "verifier": verifier,
        "cleanup_unpinned": unpinned,
    }


def load_bpf_program_with_libbpf_loader(
    *,
    object_file: str,
    pin_path: str,
    timeout: int = 60,
    cleanup_on_failure: bool = True,
    cleanup_existing_pin: bool = True,
) -> Dict[str, Any]:
    pin = Path(pin_path)
    pin.parent.mkdir(parents=True, exist_ok=True)

    pre_unpinned_existing = False
    if cleanup_existing_pin:
        pre_unpinned_existing = safe_unpin(str(pin))
        safe_unpin_links_flat(str(pin))

    build_info = _build_libbpf_loader(timeout=timeout)
    if not build_info["success"]:
        err_text = (build_info.get("stderr") or "") + "\n" + (build_info.get("stdout") or "")
        err_text = err_text.strip() or "loader build failed"
        return {
            "success": False,
            "stage": "load",
            "object_file": str(object_file),
            "pin_path": str(pin),
            "via_libbpf_loader": True,
            "pre_unpinned_existing": pre_unpinned_existing,
            "command": build_info["command"],
            "stdout": build_info["stdout"],
            "stderr": build_info["stderr"],
            "returncode": build_info["returncode"],
            "timed_out": build_info["timed_out"],
            "verifier": parse_verifier_log((build_info["stdout"] or "") + "\n" + (build_info["stderr"] or "")),
            "cleanup_unpinned": False,
            "loader_build_failed": True,
            "error_message": err_text,
            "loader_bin": build_info.get("loader_bin"),
        }

    cmd = ["sudo", build_info["loader_bin"], "--obj", str(object_file), "--pin-path", str(pin)]
    run_result = run_command(cmd, timeout=timeout)
    combined_log = _force_text(run_result.get("stdout")) + "\n" + _force_text(run_result.get("stderr"))
    success = run_result["returncode"] == 0 and not run_result["timed_out"]
    err_message = combined_log.strip() if not success else None

    attached_count = None
    link_pin_supported = None
    if success:
        m = re.search(r"\bloaded=(\d+)\s+attached=(\d+)\s+link_pin_supported=(\d+)\b", run_result["stdout"] or "")
        if m:
            attached_count = int(m.group(2))
            link_pin_supported = bool(int(m.group(3)))

    cleanup_done = False
    if not success and cleanup_on_failure:
        unpinned = safe_unpin(str(pin))
        unlinked = safe_unpin_links_flat(str(pin))
        cleanup_done = unpinned and unlinked

    return {
        "success": success,
        "stage": "load",
        "object_file": str(object_file),
        "pin_path": str(pin),
        "via_libbpf_loader": True,
        "pre_unpinned_existing": pre_unpinned_existing,
        "command": cmd,
        "stdout": _force_text(run_result.get("stdout")),
        "stderr": _force_text(run_result.get("stderr")),
        "returncode": run_result["returncode"],
        "timed_out": run_result["timed_out"],
        "verifier": parse_verifier_log(combined_log if not success else ""),
        "cleanup_unpinned": cleanup_done,
        "error_message": err_message,
        "loader_bin": build_info["loader_bin"],
        "attached_count": attached_count,
        "link_pin_supported": link_pin_supported,
    }

