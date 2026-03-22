"""Static compatibility checks based on source summary + kernel profile.

Note: We intentionally avoid requiring clang AST artifacts at runtime. Callers may pass
lightweight summaries (e.g. only `source_file`), and this module will derive missing
fields directly from the source text when needed.
"""

import json
import re
from pathlib import Path

# When False, skip helper/map/program-type *minimum kernel version* gates.
# (bpftool whitelist, GPL helper license, attach target, BTF-for-fentry, etc. still apply.)
ENABLE_MIN_KERNEL_CHECKS = False

# Curated minimal GPL-only helper set. Can be extended via rules later.
GPL_ONLY_HELPERS = {
    "bpf_probe_write_user",
}

HELPER_MIN_KERNEL = {
    "bpf_ringbuf_reserve": (5, 8),
    "bpf_ringbuf_submit": (5, 8),
    "bpf_ringbuf_discard": (5, 8),
    "bpf_ringbuf_output": (5, 8),
    "bpf_get_ns_current_pid_tgid": (5, 7),
}

HELPER_PROGRAM_ALLOWLIST = {
    "bpf_probe_write_user": {"kprobe", "kretprobe", "tracepoint", "raw_tracepoint", "perf_event"},
}

MAP_TYPE_MIN_KERNEL = {
    "BPF_MAP_TYPE_RINGBUF": (5, 8),
    "BPF_MAP_TYPE_LRU_HASH": (4, 10),
    "BPF_MAP_TYPE_LRU_PERCPU_HASH": (4, 10),
    "BPF_MAP_TYPE_HASH_OF_MAPS": (4, 12),
}

PROGRAM_TYPE_MIN_KERNEL = {
    "kprobe": (4, 1),
    "kretprobe": (4, 1),
    "tracepoint": (4, 7),
    "raw_tracepoint": (4, 17),
    "xdp": (4, 8),
    "cgroup_skb": (4, 10),
    "fentry": (5, 5),
    "fexit": (5, 5),
    "lsm": (5, 7),
    "iter": (5, 8),
}

CORE_USAGE_PATTERNS = [
    r"\bBPF_CORE_READ\b",
    r"\bbpf_core_read\b",
    r"__builtin_preserve_access_index",
    r"#\s*include\s*[<\"]vmlinux\.h[>\"]",
]


def _kernel_tuple(kernel_profile):
    version = kernel_profile.get("kernel_version", {})
    return version.get("major"), version.get("minor")


def _version_lt(current, minimum):
    major, minor = current
    if major is None or minor is None:
        return False
    return (major, minor) < minimum


def _normalize_program_type(sec_value):
    """Map SEC() first segment to a slug aligned with kernel_profile program_type_support."""
    prefix = sec_value.split("/", 1)[0]
    if prefix.startswith("raw_tp") or prefix == "raw_tracepoint":
        return "raw_tracepoint"
    if prefix == "cgroup":
        return "cgroup_skb"
    if prefix.startswith("cgroup_"):
        return prefix
    if prefix in {"kprobe", "kretprobe", "tracepoint", "xdp", "lsm", "iter", "fentry", "fexit"}:
        return prefix
    return prefix


def _extract_sections(source_text):
    return re.findall(r'SEC\("([^"]+)"\)', source_text)


def _extract_license(source_text):
    m = re.search(r'SEC\("license"\)\s*=\s*"([^"]+)"', source_text)
    if m:
        return m.group(1)
    m = re.search(r'char\s+LICENSE\[\]\s+SEC\("license"\)\s*=\s*"([^"]+)"', source_text)
    return m.group(1) if m else ""


def _extract_map_types(source_text):
    return sorted(set(re.findall(r"\bBPF_MAP_TYPE_[A-Z0-9_]+\b", source_text)))


def _uses_core_path(source_text):
    for pattern in CORE_USAGE_PATTERNS:
        if re.search(pattern, source_text):
            return True
    return False


def _supported_set(values):
    supported = set()
    for item in values:
        val = str(item).strip()
        if not val:
            continue
        supported.add(val)
        if val.startswith("BPF_MAP_TYPE_"):
            supported.add(val.replace("BPF_MAP_TYPE_", "", 1))
        if val.startswith("have_") and val.endswith("_map_type"):
            core = val[len("have_") : -len("_map_type")].upper()
            canonical = f"BPF_MAP_TYPE_{core}"
            supported.add(canonical)
            supported.add(core)
    return supported


def _target_exists(symbol):
    kallsyms = Path("/proc/kallsyms")
    if not kallsyms.exists():
        return None
    try:
        with open(kallsyms, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == symbol:
                    return True
    except OSError:
        return None
    return False


def _issue(check, level, code, message, suggestion, evidence):
    return {
        "check": check,
        "level": level,
        "code": code,
        "message": message,
        "suggestion": suggestion,
        "evidence": evidence,
    }


def analyze_single_source(summary, kernel_profile):
    source_file = summary.get("source_file", "")
    source_path = Path(source_file)
    source_text = source_path.read_text(encoding="utf-8", errors="ignore") if source_path.exists() else ""

    kernel_ver = _kernel_tuple(kernel_profile)
    helper_whitelist = set(kernel_profile.get("helper_whitelist", []))
    map_support = _supported_set(kernel_profile.get("map_type_support", []))
    program_type_support = set(kernel_profile.get("program_type_support", []))
    btf_available = bool(kernel_profile.get("btf", {}).get("available", False))

    sections = _extract_sections(source_text)
    license_text = _extract_license(source_text)
    map_types = _extract_map_types(source_text)
    # AST 失败（clang/JSON）时明确不走摘要里的 helper 列表，强制源码正则回退
    if summary.get("ast_fallback"):
        helper_calls = []
    else:
        helper_calls = [
            x.get("helper")
            for x in summary.get("bpf_helper_calls", [])
            if isinstance(x, dict) and x.get("helper")
        ]
    if not helper_calls:
        candidates = re.findall(r"\b(bpf_[A-Za-z0-9_]+)\s*\(", source_text or "")
        policy_known = set(HELPER_MIN_KERNEL) | set(GPL_ONLY_HELPERS) | set(HELPER_PROGRAM_ALLOWLIST)
        if helper_whitelist:
            # 必须保留源码里出现的全部 bpf_*，否则「不在白名单里的新 helper」会被提前过滤掉，
            # 例如 helper_absent 里的 bpf_get_current_task_btf 在旧内核上不会出现在 bpftool whitelist。
            helper_calls = sorted(set(candidates))
        else:
            helper_calls = [c for c in candidates if c in policy_known]

    program_sections = [s for s in sections if s not in {".maps", "license"}]
    program_types = [_normalize_program_type(sec) for sec in program_sections]

    issues = []

    for helper in helper_calls:
        if ENABLE_MIN_KERNEL_CHECKS:
            min_ver = HELPER_MIN_KERNEL.get(helper)
            if min_ver and _version_lt(kernel_ver, min_ver):
                issues.append(
                    _issue(
                        "helper_availability",
                        "error",
                        "helper_min_kernel",
                        f"Helper {helper} requires kernel >= {min_ver[0]}.{min_ver[1]}.",
                        "Use fallback helper sequence from static rules or choose another helper.",
                        {"helper": helper, "kernel": kernel_profile.get("kernel_version", {}).get("raw")},
                    )
                )

        if helper_whitelist and helper not in helper_whitelist:
            issues.append(
                _issue(
                    "helper_availability",
                    "error",
                    "helper_not_in_probe",
                    f"Helper {helper} is not present in bpftool helper whitelist.",
                    "Replace helper with compatible one or deploy to a kernel supporting this helper.",
                    {"helper": helper},
                )
            )

        allowlist = HELPER_PROGRAM_ALLOWLIST.get(helper)
        if allowlist and any(pt not in allowlist for pt in program_types):
            issues.append(
                _issue(
                    "helper_availability",
                    "error",
                    "helper_program_type_mismatch",
                    f"Helper {helper} is not allowed for one or more SEC program types.",
                    "Move helper usage to a compatible program type or refactor logic.",
                    {"helper": helper, "program_types": program_types},
                )
            )

        if helper in GPL_ONLY_HELPERS and "GPL" not in license_text.upper():
            issues.append(
                _issue(
                    "helper_availability",
                    "error",
                    "gpl_helper_license_mismatch",
                    f"GPL-only helper {helper} requires SEC(\"license\") to contain GPL.",
                    'Set license to GPL-compatible string, e.g. "GPL".',
                    {"helper": helper, "license": license_text},
                )
            )

    for map_type in map_types:
        if ENABLE_MIN_KERNEL_CHECKS:
            min_ver = MAP_TYPE_MIN_KERNEL.get(map_type)
            if min_ver and _version_lt(kernel_ver, min_ver):
                issues.append(
                    _issue(
                        "map_type_availability",
                        "error",
                        "map_type_min_kernel",
                        f"Map type {map_type} requires kernel >= {min_ver[0]}.{min_ver[1]}.",
                        "Use downgrade rule to supported map type on target kernel.",
                        {"map_type": map_type},
                    )
                )

        normalized = map_type.replace("BPF_MAP_TYPE_", "", 1)
        if map_support and map_type not in map_support and normalized not in map_support:
            issues.append(
                _issue(
                    "map_type_availability",
                    "error",
                    "map_type_not_in_probe",
                    f"Map type {map_type} is not present in bpftool map type support list.",
                    "Switch to supported map type or enable kernel feature.",
                    {"map_type": map_type},
                )
            )

    for sec in program_sections:
        ptype = _normalize_program_type(sec)
        if program_type_support and ptype not in program_type_support:
            issues.append(
                _issue(
                    "program_type_attach_availability",
                    "error",
                    "program_type_not_supported",
                    f'Program type "{ptype}" from SEC("{sec}") is not in bpftool program type support list for this kernel.',
                    "Use a program type listed in kernel_profile program_type_support, or upgrade the kernel / bpftool probe environment.",
                    {"sec": sec, "program_type": ptype},
                )
            )

        if ENABLE_MIN_KERNEL_CHECKS:
            min_ver = PROGRAM_TYPE_MIN_KERNEL.get(ptype)
            if min_ver and _version_lt(kernel_ver, min_ver):
                issues.append(
                    _issue(
                        "program_type_attach_availability",
                        "error",
                        "program_type_min_kernel",
                        f'SEC("{sec}") requires kernel >= {min_ver[0]}.{min_ver[1]}.',
                        "Change SEC program type or use a newer kernel.",
                        {"sec": sec},
                    )
                )

        if ptype in {"fentry", "fexit"} and not btf_available:
            issues.append(
                _issue(
                    "program_type_attach_availability",
                    "error",
                    "fentry_fexit_require_btf",
                    f'SEC("{sec}") requires BTF-enabled kernel.',
                    "Switch to kprobe/tracepoint fallback when BTF is unavailable.",
                    {"sec": sec},
                )
            )

        if ptype in {"kprobe", "kretprobe", "fentry", "fexit"}:
            if "/" not in sec or not sec.split("/", 1)[1]:
                issues.append(
                    _issue(
                        "program_type_attach_availability",
                        "error",
                        "missing_attach_target",
                        f'SEC("{sec}") is missing attach target symbol.',
                        "Use SEC with explicit target, e.g. kprobe/__x64_sys_execve.",
                        {"sec": sec},
                    )
                )
            else:
                target = sec.split("/", 1)[1]
                exists = _target_exists(target)
                if exists is False:
                    issues.append(
                        _issue(
                            "program_type_attach_availability",
                            "warning",
                            "attach_target_not_found",
                            f"Attach target {target} not found in /proc/kallsyms on current host.",
                            "Verify target symbol on deployment kernel or adjust attach target.",
                            {"sec": sec, "target": target},
                        )
                    )

        if ptype == "tracepoint":
            parts = sec.split("/")
            if len(parts) < 3 or not parts[1] or not parts[2]:
                issues.append(
                    _issue(
                        "program_type_attach_availability",
                        "error",
                        "invalid_tracepoint_sec",
                        f'SEC("{sec}") must be tracepoint/<category>/<event>.',
                        "Fix SEC declaration to include category and event.",
                        {"sec": sec},
                    )
                )

    if _uses_core_path(source_text) and not btf_available:
        issues.append(
            _issue(
                "core_btf_precondition",
                "error",
                "core_requires_btf",
                "CO-RE/BPF_CORE_READ path detected but target kernel has no /sys/kernel/btf/vmlinux.",
                "Must switch to non-CO-RE downgrade path (e.g., bpf_probe_read_kernel with offsets).",
                {"source_file": source_file},
            )
        )

    return {
        "source_file": source_file,
        "program_sections": program_sections,
        "program_types": program_types,
        "license": license_text,
        "map_types": map_types,
        "helper_calls": helper_calls,
        "issues": issues,
    }


def _build_report(results):
    error_count = 0
    warning_count = 0
    for res in results:
        for issue in res.get("issues") or []:
            if issue["level"] == "error":
                error_count += 1
            elif issue["level"] == "warning":
                warning_count += 1

    flat_issues = []
    for res in results:
        for issue in res.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            flat = dict(issue)
            flat.setdefault("source_file", res.get("source_file"))
            flat_issues.append(flat)

    return {
        "success": error_count == 0,
        "error_warning_count": {"error": error_count, "warning": warning_count},
        "issues": flat_issues,
    }


def analyze_case_static_checks(summaries, kernel_profile, output_path=None):
    results = [analyze_single_source(s, kernel_profile) for s in summaries]
    report = _build_report(results)
    report["results"] = results
    report["summary"] = {
        "error_count": int((report.get("error_warning_count") or {}).get("error") or 0),
        "warning_count": int((report.get("error_warning_count") or {}).get("warning") or 0),
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=True)

    return report

