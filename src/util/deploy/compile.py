from __future__ import annotations

import json
import platform
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.util.deploy.commands import run_command


CORE_PATTERNS = [
    r"\bBPF_CORE_READ\b",
    r"\bbpf_core_read\b",
    r"__builtin_preserve_access_index",
    r"#\s*include\s*[<\"]vmlinux\.h[>\"]",
]

ARCH_TO_TARGET = {
    "x86_64": "x86",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "arm",
    "s390x": "s390",
    "mips": "mips",
    "mips64": "mips",
    "ppc64le": "powerpc",
    "ppc64": "powerpc",
    "riscv64": "riscv",
}


def _generate_vmlinux_header(
    header_path: str | Path,
    *,
    bpftool_bin: str = "bpftool",
    kernel_btf_path: str = "/sys/kernel/btf/vmlinux",
    timeout: int = 60,
) -> Dict[str, Any]:
    header = Path(header_path)
    header.parent.mkdir(parents=True, exist_ok=True)

    cmd = [bpftool_bin, "btf", "dump", "file", kernel_btf_path, "format", "c"]
    result = run_command(cmd, timeout=timeout)
    if result["returncode"] != 0 or result["timed_out"]:
        return {
            "success": False,
            "command": cmd,
            "returncode": result["returncode"],
            "timed_out": result["timed_out"],
            "stderr": result["stderr"],
            "header_path": str(header),
        }

    try:
        header.write_text(result["stdout"], encoding="utf-8")
    except OSError as exc:
        return {
            "success": False,
            "command": cmd,
            "returncode": None,
            "timed_out": False,
            "stderr": str(exc),
            "header_path": str(header),
        }

    return {
        "success": True,
        "command": cmd,
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "stderr": result["stderr"],
        "header_path": str(header),
    }


def _btf_member_bit_offset(
    *,
    bpftool_bin: str,
    kernel_btf_path: str,
    struct_name: str,
    member_name: str,
    timeout: int = 20,
) -> tuple[bool, Optional[int], Optional[str]]:
    cmd = [bpftool_bin, "btf", "dump", "file", kernel_btf_path, "format", "raw", "-j"]
    result = run_command(cmd, timeout=timeout)
    if result["returncode"] != 0 or result["timed_out"]:
        err = (result.get("stderr") or "") + "\n" + (result.get("stdout") or "")
        return False, None, (err.strip() or "btf_dump_failed")

    try:
        payload = json.loads(result["stdout"] or "[]")
    except json.JSONDecodeError as exc:
        return False, None, f"btf_dump_json_decode_failed: {exc}"

    for t in payload if isinstance(payload, list) else []:
        if not isinstance(t, dict):
            continue
        if t.get("kind") != "struct":
            continue
        if t.get("name") != struct_name:
            continue
        for m in t.get("members") or []:
            if isinstance(m, dict) and m.get("name") == member_name and "bit_offset" in m:
                try:
                    return True, int(m["bit_offset"]), None
                except (TypeError, ValueError):
                    return False, None, "btf_member_bit_offset_invalid"
        return False, None, "btf_member_not_found"

    return False, None, "btf_struct_not_found"


def maybe_inject_task_tgid_offset(
    extra_cflags: Optional[List[str]],
    *,
    source_file: str,
    bpftool_bin: str = "bpftool",
    kernel_btf_path: str = "/sys/kernel/btf/vmlinux",
) -> Optional[List[str]]:
    src = Path(source_file)
    try:
        text = src.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return extra_cflags

    if "TASK_TGID_OFFSET" not in text:
        return extra_cflags

    ok, bit_off, _err = _btf_member_bit_offset(
        bpftool_bin=bpftool_bin,
        kernel_btf_path=kernel_btf_path,
        struct_name="task_struct",
        member_name="tgid",
    )
    if not ok or bit_off is None:
        return extra_cflags

    byte_off = bit_off // 8
    flags = list(extra_cflags or [])
    flags.append(f"-DTASK_TGID_OFFSET=0x{byte_off:x}")
    return flags


def _detect_core_mode(source_file: str | Path) -> bool:
    source = Path(source_file)
    try:
        text = source.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    for pattern in CORE_PATTERNS:
        if re.search(pattern, text):
            return True
    return False


def _target_arch_define() -> str:
    machine = platform.machine().lower()
    return ARCH_TO_TARGET.get(machine, machine)


def compile_bpf_program(
    *,
    source_file: str,
    object_file: Optional[str] = None,
    clang_bin: str = "clang",
    optimize: str = "-O2",
    debug: bool = True,
    mcpu: Optional[str] = None,
    compile_mode: str = "auto",
    bpftool_bin: str = "bpftool",
    kernel_btf_path: str = "/sys/kernel/btf/vmlinux",
    vmlinux_header_dir: Optional[str] = None,
    extra_cflags: Optional[List[str]] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    source = Path(source_file)
    obj = Path(object_file) if object_file else source.with_suffix(".o")

    if compile_mode not in {"auto", "core", "non-core"}:
        raise ValueError("compile_mode must be one of: auto, core, non-core")

    if compile_mode == "auto":
        core_mode = _detect_core_mode(source)
        effective_mode = "core" if core_mode else "non-core"
    else:
        effective_mode = compile_mode

    cmd: List[str] = [clang_bin, optimize]
    if debug:
        cmd.insert(2, "-g")

    cmd.extend(["-target", "bpf"])

    vmlinux_header: Optional[Path] = None
    vmlinux_generation: Optional[Dict[str, Any]] = None

    if effective_mode == "core":
        header_dir = Path(vmlinux_header_dir) if vmlinux_header_dir else obj.parent
        vmlinux_header = header_dir / "vmlinux.h"

        if not vmlinux_header.exists():
            vmlinux_generation = _generate_vmlinux_header(
                vmlinux_header,
                bpftool_bin=bpftool_bin,
                kernel_btf_path=kernel_btf_path,
                timeout=timeout,
            )
            if not vmlinux_generation["success"]:
                try:
                    fallback = (
                        Path(__file__).resolve().parents[3] / "scripts" / "setup" / "vmlinux_fallback" / "vmlinux.h"
                    )
                    vmlinux_header.parent.mkdir(parents=True, exist_ok=True)
                    vmlinux_header.write_text(fallback.read_text(encoding="utf-8"), encoding="utf-8")
                    effective_mode = "non-core"
                except OSError:
                    return {
                        "success": False,
                        "stage": "compile",
                        "source_file": str(source),
                        "object_file": str(obj),
                        "compile_mode": effective_mode,
                        "command": cmd,
                        "stdout": "",
                        "stderr": (
                            "Failed to generate vmlinux.h for CO-RE compile. "
                            f"stderr: {vmlinux_generation['stderr']}"
                        ),
                        "returncode": vmlinux_generation["returncode"],
                        "timed_out": vmlinux_generation["timed_out"],
                        "vmlinux_header": str(vmlinux_header),
                        "vmlinux_generation": vmlinux_generation,
                    }

        if effective_mode == "core":
            cmd.extend(
                [
                    f"-D__TARGET_ARCH_{_target_arch_define()}",
                    f"-I{vmlinux_header.parent}",
                    f"-I{source.parent}",
                ]
            )
        else:
            cmd.extend([f"-I{vmlinux_header.parent}", f"-I{source.parent}"])
    else:
        arch_include = f"/usr/include/{platform.machine()}-linux-gnu"
        cmd.extend([f"-I{arch_include}"])

    cmd.extend(["-c", str(source), "-o", str(obj)])

    if mcpu:
        cmd.extend(["-mcpu", mcpu])
    if extra_cflags:
        cmd.extend(extra_cflags)

    result = run_command(cmd, timeout=timeout)
    return {
        "success": result["returncode"] == 0 and not result["timed_out"],
        "stage": "compile",
        "source_file": str(source),
        "object_file": str(obj),
        "compile_mode": effective_mode,
        "vmlinux_header": str(vmlinux_header) if vmlinux_header else None,
        "vmlinux_generation": vmlinux_generation,
        "command": cmd,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
    }

