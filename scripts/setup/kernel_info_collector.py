import gzip
import json
import os
import re
import subprocess
from pathlib import Path


def _run_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "cmd": cmd,
    }


def _parse_kernel_release(release):
    # Example: 5.15.0-105-generic -> major/minor/patch + distro suffix.
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", release or "")
    if not m:
        return {
            "raw": release,
            "major": None,
            "minor": None,
            "patch": None,
            "distro_suffix": "",
        }
    return {
        "raw": release,
        "major": int(m.group(1)),
        "minor": int(m.group(2)),
        "patch": int(m.group(3)),
        "distro_suffix": m.group(4),
    }


def _version_at_least(major, minor, target_major, target_minor):
    if major is None or minor is None:
        return False
    return (major, minor) >= (target_major, target_minor)


def _read_kernel_config():
    config_path = None
    config_text = ""
    errors = []

    if os.path.exists("/proc/config.gz"):
        config_path = "/proc/config.gz"
        try:
            with gzip.open(config_path, "rt", encoding="utf-8", errors="ignore") as f:
                config_text = f.read()
        except OSError as e:
            errors.append(str(e))
    else:
        release = _run_cmd(["uname", "-r"])["stdout"]
        boot_config = f"/boot/config-{release}"
        if os.path.exists(boot_config):
            config_path = boot_config
            try:
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    config_text = f.read()
            except OSError as e:
                errors.append(str(e))

    bpf_flags = {}
    if config_text:
        for line in config_text.splitlines():
            if line.startswith("CONFIG_BPF_"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    bpf_flags[key.strip()] = value.strip()

    return {
        "source": config_path,
        "available": bool(config_text),
        "bpf_flags": bpf_flags,
        "errors": errors,
        "raw_text": config_text,
    }


def _collect_bpftool_features():
    attempts = [
        {
            "cmd": ["sudo", "-n", "bpftool", "-j", "feature", "probe", "kernel", "full"],
            "privileged": True,
        },
        {
            "cmd": ["bpftool", "-j", "feature", "probe", "kernel", "full"],
            "privileged": True,
        },
        {
            "cmd": ["bpftool", "-j", "feature", "probe", "kernel"],
            "privileged": False,
        },
        {
            "cmd": ["bpftool", "-j", "feature", "probe", "kernel", "unprivileged"],
            "privileged": False,
        },
        {
            "cmd": ["bpftool", "-j", "feature", "probe"],
            "privileged": False,
        },
    ]

    last_error = ""
    for attempt in attempts:
        cmd = attempt["cmd"]
        result = _run_cmd(cmd)
        if not result["ok"]:
            last_error = result["stderr"] or f"return code {result['returncode']}"
            continue
        try:
            parsed = json.loads(result["stdout"])
            return {
                "available": True,
                "command": " ".join(cmd),
                "privileged": attempt["privileged"],
                "json": parsed,
                "stderr": result["stderr"],
                "error": "",
            }
        except json.JSONDecodeError as e:
            last_error = str(e)

    return {
        "available": False,
        "command": "",
        "privileged": False,
        "json": {},
        "stderr": "",
        "error": last_error or "bpftool feature probe unavailable",
    }


def _collect_strings_by_key_fragment(node, fragment, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if fragment in k.lower():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            out.add(item)
                        elif isinstance(item, dict):
                            name = item.get("name")
                            if isinstance(name, str):
                                out.add(name)
                elif isinstance(v, dict):
                    for key, value in v.items():
                        if isinstance(value, bool) and value:
                            out.add(str(key))
                        elif isinstance(value, str) and value.lower() in {"y", "yes", "true", "supported"}:
                            out.add(str(key))
                        elif isinstance(value, str) and key == "name":
                            out.add(value)
            _collect_strings_by_key_fragment(v, fragment, out)
    elif isinstance(node, list):
        for item in node:
            _collect_strings_by_key_fragment(item, fragment, out)


def _extract_helpers_and_maps(bpftool_json):
    helper_set = set()
    map_set = set()
    _collect_strings_by_key_fragment(bpftool_json, "helper", helper_set)
    _collect_strings_by_key_fragment(bpftool_json, "map", map_set)

    # Filter map-type like names, avoid unrelated map keys from generic JSON.
    filtered_maps = sorted(
        {
            item
            for item in map_set
            if item.startswith("BPF_MAP_TYPE_") or item.startswith("map_") or "map" in item.lower()
        }
    )
    return sorted(helper_set), filtered_maps


def _collect_clang_info():
    result = _run_cmd(["clang", "--version"])
    first_line = result["stdout"].splitlines()[0] if result["stdout"] else ""
    version = None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", first_line)
    if m:
        version = {
            "major": int(m.group(1)),
            "minor": int(m.group(2)),
            "patch": int(m.group(3)) if m.group(3) is not None else 0,
        }
    return {
        "available": result["ok"],
        "version_line": first_line,
        "version": version,
        "error": "" if result["ok"] else (result["stderr"] or "clang not found"),
    }


def _infer_verifier_limits(kernel_version):
    major = kernel_version.get("major")
    minor = kernel_version.get("minor")
    return {
        "bounded_loops_supported": _version_at_least(major, minor, 5, 2),
        "ring_buffer_supported": _version_at_least(major, minor, 5, 8),
        "legacy_stack_limit_bytes": 512 if not _version_at_least(major, minor, 5, 3) else 512,
        "note": "Inferred by kernel version thresholds from project plan.",
    }


def collect_kernel_info(output_path="kernel_profile.json", artifacts_dir=None, bpftool_output_path=None):
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    uname_release = _run_cmd(["uname", "-r"])["stdout"]
    kernel_version = _parse_kernel_release(uname_release)
    config_info = _read_kernel_config()

    btf_path = Path("/sys/kernel/btf/vmlinux")
    btf_available = btf_path.exists()
    btf_size = btf_path.stat().st_size if btf_available else 0

    bpftool_info = _collect_bpftool_features()
    helper_whitelist, map_type_support = _extract_helpers_and_maps(bpftool_info["json"])

    clang_info = _collect_clang_info()

    profile = {
        "kernel_version": kernel_version,
        "config": {
            "source": config_info["source"],
            "available": config_info["available"],
            "bpf_flags": config_info["bpf_flags"],
            "errors": config_info["errors"],
        },
        "btf": {
            "path": str(btf_path),
            "available": btf_available,
            "size_bytes": btf_size,
        },
        "helper_whitelist": helper_whitelist,
        "map_type_support": map_type_support,
        "verifier_limits": _infer_verifier_limits(kernel_version),
        "clang": clang_info,
        "bpftool_feature_probe": {
            "available": bpftool_info["available"],
            "command": bpftool_info["command"],
            "privileged": bpftool_info["privileged"],
            "error": bpftool_info["error"],
        },
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=True)

    if artifacts_dir:
        artifacts = Path(artifacts_dir)
        artifacts.mkdir(parents=True, exist_ok=True)
        with open(artifacts / "kernel_profile.json", "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=True)

    if bpftool_info["available"]:
        if bpftool_output_path:
            bpftool_output = Path(bpftool_output_path)
            bpftool_output.parent.mkdir(parents=True, exist_ok=True)
            with open(bpftool_output, "w", encoding="utf-8") as f:
                json.dump(bpftool_info["json"], f, indent=2, ensure_ascii=True)
        elif artifacts_dir:
            with open(Path(artifacts_dir) / "bpftool_feature_probe.json", "w", encoding="utf-8") as f:
                json.dump(bpftool_info["json"], f, indent=2, ensure_ascii=True)

    return profile


if __name__ == "__main__":
    collect_kernel_info()