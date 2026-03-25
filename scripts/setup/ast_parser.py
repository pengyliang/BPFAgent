"""AST parser for eBPF source based on clang JSON AST output."""

import json
import platform
import re
import subprocess
from pathlib import Path

MAP_HELPER_OPERATION = {
    "bpf_map_lookup_elem": "lookup",
    "bpf_map_lookup_percpu_elem": "lookup",
    "bpf_map_update_elem": "update",
    "bpf_map_delete_elem": "delete",
    "bpf_map_push_elem": "push",
    "bpf_map_pop_elem": "pop",
    "bpf_map_peek_elem": "peek",
}

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


def _target_arch_define():
    machine = platform.machine().lower()
    return ARCH_TO_TARGET.get(machine, machine)


def _detect_core_mode(source_file):
    source = Path(source_file)
    try:
        text = source.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    for pattern in CORE_PATTERNS:
        if re.search(pattern, text):
            return True
    return False


def _generate_vmlinux_header(header_path, bpftool_bin="bpftool", kernel_btf_path="/sys/kernel/btf/vmlinux"):
    header = Path(header_path)
    header.parent.mkdir(parents=True, exist_ok=True)
    cmd = [bpftool_bin, "btf", "dump", "file", kernel_btf_path, "format", "c"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        return {
            "success": False,
            "command": cmd,
            "stderr": result.stderr,
        }
    try:
        header.write_text(result.stdout, encoding="utf-8")
    except OSError as exc:
        return {
            "success": False,
            "command": cmd,
            "stderr": str(exc),
        }
    return {
        "success": True,
        "command": cmd,
        "stderr": result.stderr,
    }

def _walk(node):
    """Yield each AST node in depth-first order."""
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get("inner", []):
        yield from _walk(child)


def _get_location(node):
    begin = node.get("range", {}).get("begin", {})
    return {
        "line": begin.get("line"),
        "column": begin.get("col"),
        "offset": begin.get("offset"),
    }


def _extract_declref_name(node):
    if not isinstance(node, dict):
        return None

    if node.get("kind") == "DeclRefExpr":
        referenced = node.get("referencedDecl", {})
        return referenced.get("name") or node.get("name")

    for child in node.get("inner", []):
        found = _extract_declref_name(child)
        if found:
            return found
    return None


def _extract_member_path(node):
    if not isinstance(node, dict):
        return None

    kind = node.get("kind")
    if kind == "MemberExpr":
        field_name = node.get("name")
        if not field_name:
            return None

        base = None
        inner = node.get("inner", [])
        if inner:
            base = _extract_member_path(inner[0])
        if base:
            return f"{base}.{field_name}"
        return field_name

    if kind == "DeclRefExpr":
        return _extract_declref_name(node)

    for child in node.get("inner", []):
        path = _extract_member_path(child)
        if path:
            return path
    return None


def _extract_call_target_name(call_node):
    for child in call_node.get("inner", []):
        name = _extract_declref_name(child)
        if name:
            return name
    return None


def _extract_map_symbol_from_call(call_node):
    # In clang AST, first inner is callee expression, followed by args.
    args = call_node.get("inner", [])[1:]
    if not args:
        return None
    return _extract_declref_name(args[0])


def _ast_fallback_summary(file_path, *, reason: str):
    """When clang/AST fails, return a minimal summary so static_checker uses source-text heuristics."""
    return {
        "source_file": str(Path(file_path)),
        "ast_fallback": True,
        "ast_fallback_reason": reason,
        "bpf_helper_calls": [],
        "struct_field_access_paths": [],
        "map_operation_sequence": [],
    }


def _write_parser_log(log_path, source_file, command, stderr_text, success):
    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    status = "SUCCESS" if success else "FAILED"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"status: {status}\n")
        f.write(f"source_file: {source_file}\n")
        f.write(f"command: {' '.join(command)}\n")
        f.write("stderr:\n")
        f.write(stderr_text.strip() + "\n" if stderr_text else "<empty>\n")


def _extract_missing_headers(stderr_text):
    # Example: fatal error: 'foo.h' file not found
    return re.findall(r"fatal error:\s*'([^']+)'\s*file not found", stderr_text or "")


def _ensure_stub_headers(headers, stub_dir):
    base = Path(stub_dir)
    base.mkdir(parents=True, exist_ok=True)
    created = []
    for header in headers:
        # Keep relative include structure if path contains subdirs.
        header_path = base / header
        header_path.parent.mkdir(parents=True, exist_ok=True)
        if not header_path.exists():
            guard = re.sub(r"[^A-Za-z0-9]", "_", header.upper())
            header_path.write_text(
                f"#ifndef {guard}\n#define {guard}\n#endif\n",
                encoding="utf-8",
            )
            created.append(str(header_path))
    return created


def parse_ebpf_source(
    file_path,
    output_path="ast_summary.json",
    log_path="ast_parser.log",
    vmlinux_header_dir=None,
    bpftool_bin="bpftool",
    kernel_btf_path="/sys/kernel/btf/vmlinux",
):
    source = Path(file_path)
    source_dir = source.parent
    arch_include = f"/usr/include/{platform.machine()}-linux-gnu"
    stub_dir = Path(output_path).parent / "stubs"

    cmd = [
        "clang",
        "-target",
        "bpf",
        "-Xclang",
        "-ast-dump=json",
        "-fsyntax-only",
        f"-I{source_dir}",
        f"-I{arch_include}",
    ]

    if _detect_core_mode(file_path):
        header_base = Path(vmlinux_header_dir) if vmlinux_header_dir else Path(output_path).parent
        vmlinux_header = header_base / "vmlinux.h"
        if not vmlinux_header.exists():
            header_result = _generate_vmlinux_header(
                vmlinux_header,
                bpftool_bin=bpftool_bin,
                kernel_btf_path=kernel_btf_path,
            )
        if vmlinux_header.exists():
            cmd.append(f"-D__TARGET_ARCH_{_target_arch_define()}")
            cmd.append(f"-I{vmlinux_header.parent}")

    cmd.append(file_path)

    parse_result = None
    last_stderr = ""
    max_retry = 5
    used_stub_include = False
    for _ in range(max_retry):
        parse_result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        last_stderr = parse_result.stderr
        missing = _extract_missing_headers(parse_result.stderr)
        if not missing:
            break

        _ensure_stub_headers(missing, stub_dir)
        if not used_stub_include:
            cmd.insert(-1, f"-I{stub_dir}")
            used_stub_include = True

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_text = (parse_result.stdout if parse_result else "") or ""
    rc = parse_result.returncode if parse_result is not None else -1

    # Clang failed or produced no AST JSON → static_checker 走源码正则等回退逻辑
    if rc != 0 or not stdout_text.strip():
        reason = f"clang_exit_{rc}" if rc != 0 else "empty_clang_stdout"
        fb = _ast_fallback_summary(file_path, reason=reason)
        _write_parser_log(log_path, file_path, cmd, last_stderr, False)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(fb, f, indent=2, ensure_ascii=True)
        print(f"AST skipped ({reason}); static check will use source-text analysis. See {log_path}")
        return fb

    try:
        # Parse stdout as JSON AST whenever available, even if clang has diagnostics.
        ast_root = json.loads(stdout_text)
        ok = bool(stdout_text.strip())
        _write_parser_log(log_path, file_path, cmd, last_stderr, ok)

        helper_calls = []
        struct_access_paths = []
        map_operations = []

        for node in _walk(ast_root):
            kind = node.get("kind")

            if kind == "CallExpr":
                helper_name = _extract_call_target_name(node)
                if helper_name and helper_name.startswith("bpf_"):
                    loc = _get_location(node)
                    helper_calls.append(
                        {
                            "helper": helper_name,
                            "line": loc["line"],
                            "column": loc["column"],
                        }
                    )

                    operation = MAP_HELPER_OPERATION.get(helper_name)
                    if operation:
                        map_operations.append(
                            {
                                "step": len(map_operations) + 1,
                                "operation": operation,
                                "helper": helper_name,
                                "map_symbol": _extract_map_symbol_from_call(node),
                                "line": loc["line"],
                                "column": loc["column"],
                            }
                        )

            if kind == "MemberExpr":
                path = _extract_member_path(node)
                if path:
                    loc = _get_location(node)
                    struct_access_paths.append(
                        {
                            "path": path,
                            "line": loc["line"],
                            "column": loc["column"],
                        }
                    )

        # De-duplicate while preserving order.
        seen_paths = set()
        unique_struct_access_paths = []
        for item in struct_access_paths:
            key = (item["path"], item["line"], item["column"])
            if key not in seen_paths:
                seen_paths.add(key)
                unique_struct_access_paths.append(item)

        ast_summary = {
            "source_file": str(Path(file_path)),
            "ast_fallback": False,
            "bpf_helper_calls": helper_calls,
            "struct_field_access_paths": unique_struct_access_paths,
            "map_operation_sequence": map_operations,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(ast_summary, f, indent=2, ensure_ascii=True)
        # print(f"AST successfully parsed and saved to {output_path}")
        return ast_summary
    except json.JSONDecodeError:
        _write_parser_log(log_path, file_path, cmd, last_stderr, False)
        fb = _ast_fallback_summary(file_path, reason="ast_json_decode_error")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(fb, f, indent=2, ensure_ascii=True)
        print(f"Error parsing AST JSON. Check {log_path} for details; static check will use source-text analysis.")
        return fb

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python ast_parser.py <source_file>")
    else:
        parse_ebpf_source(sys.argv[1])