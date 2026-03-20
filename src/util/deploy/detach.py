from __future__ import annotations

from typing import Any, Dict

from src.util.deploy.load import safe_unpin, safe_unpin_links_flat, terminate_loader_daemon_by_pin_path


def detach_bpf_program(*, pin_path: str, attach_result: Dict[str, Any]) -> Dict[str, Any]:
    detach_cmd = ["sudo", "rm", "-f", str(pin_path)]
    terminated = False
    if not attach_result or not attach_result.get("success"):
        return {
            "success": False,
            "stage": "detach",
            "detached": False,
            "skipped": True,
            "reason": "attach_failed",
            "command": detach_cmd,
            "pin_path": pin_path,
        }

    if attach_result.get("skipped") or not attach_result.get("attached"):
        return {
            "success": True,
            "stage": "detach",
            "detached": False,
            "skipped": True,
            "reason": "attach_skipped",
            "command": detach_cmd,
            "pin_path": pin_path,
        }

    if attach_result.get("via_libbpf_loader_daemon"):
        terminated = terminate_loader_daemon_by_pin_path(str(pin_path))

    detached = safe_unpin(pin_path)
    links_removed = safe_unpin_links_flat(pin_path)
    return {
        "success": detached and links_removed and (terminated or not attach_result.get("via_libbpf_loader_daemon")),
        "stage": "detach",
        "detached": detached and links_removed and (terminated or not attach_result.get("via_libbpf_loader_daemon")),
        "skipped": False,
        "reason": (
            "loader_terminated_and_unpinned"
            if attach_result.get("via_libbpf_loader_daemon") and terminated and detached and links_removed
            else ("unpinned" if (detached and links_removed) else "unpin_failed")
        ),
        "command": detach_cmd,
        "pin_path": pin_path,
        "links_removed": links_removed,
        "loader_processes_terminated": terminated,
    }

