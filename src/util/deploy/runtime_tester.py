"""Runtime validator: run workload and check map value against validator.yaml."""

import json
import re
import subprocess
from pathlib import Path


def _default_run_command(cmd, timeout=60, cwd=None):
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "command": cmd,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": cmd,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
        }


def _parse_scalar(text):
    raw = str(text).strip()
    if raw.startswith(("\"", "'")) and raw.endswith(("\"", "'")) and len(raw) >= 2:
        raw = raw[1:-1]

    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def _load_simple_yaml(path):
    payload = {}
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        payload[key.strip()] = _parse_scalar(value)
    return payload


def _u32_to_hex_key(key_value):
    as_int = int(key_value)
    if as_int < 0:
        raise ValueError("validator key must be non-negative")
    b = as_int.to_bytes(4, byteorder="little", signed=False)
    return [f"{x:02x}" for x in b]


def _extract_program_info(pin_path, bpftool_bin, run_command):
    cmd = ["sudo", bpftool_bin, "prog", "show", "pinned", str(pin_path), "-j"]
    result = run_command(cmd, timeout=20)
    if result["timed_out"]:
        return None, None, result

    try:
        parsed = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError:
        if result["returncode"] != 0:
            return None, None, result
        return None, None, result

    if isinstance(parsed, list):
        prog = parsed[0] if parsed else {}
    elif isinstance(parsed, dict):
        prog = parsed
    else:
        prog = {}

    prog_id = prog.get("id")
    map_ids = prog.get("map_ids") or []

    # With autoattach, pin path may be a BPF link object. Resolve to prog_id first.
    if (not prog_id) and isinstance(parsed, dict) and parsed.get("error"):
        err = str(parsed.get("error") or "").lower()
        if "incorrect object type" in err and "link" in err:
            link_cmd = ["sudo", bpftool_bin, "link", "show", "pinned", str(pin_path), "-j"]
            link_result = run_command(link_cmd, timeout=20)
            if not link_result["timed_out"]:
                try:
                    link_parsed = json.loads(link_result["stdout"] or "{}")
                except json.JSONDecodeError:
                    link_parsed = {}

                if isinstance(link_parsed, list):
                    link_item = link_parsed[0] if link_parsed else {}
                elif isinstance(link_parsed, dict):
                    link_item = link_parsed
                else:
                    link_item = {}

                prog_id = link_item.get("prog_id")
                if prog_id:
                    by_id_cmd = ["sudo", bpftool_bin, "prog", "show", "id", str(prog_id), "-j"]
                    by_id_result = run_command(by_id_cmd, timeout=20)
                    if by_id_result["returncode"] == 0 and not by_id_result["timed_out"]:
                        try:
                            by_id_parsed = json.loads(by_id_result["stdout"] or "{}")
                        except json.JSONDecodeError:
                            by_id_parsed = {}

                        if isinstance(by_id_parsed, list):
                            prog_by_id = by_id_parsed[0] if by_id_parsed else {}
                        elif isinstance(by_id_parsed, dict):
                            prog_by_id = by_id_parsed
                        else:
                            prog_by_id = {}
                        map_ids = prog_by_id.get("map_ids") or []

    return prog_id, map_ids, result


def _map_info_by_id(map_id, bpftool_bin, run_command):
    cmd = ["sudo", bpftool_bin, "map", "show", "id", str(map_id), "-j"]
    result = run_command(cmd, timeout=20)
    if result["returncode"] != 0 or result["timed_out"]:
        return None, result

    try:
        parsed = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError:
        return None, result

    if isinstance(parsed, list):
        return (parsed[0] if parsed else None), result
    if isinstance(parsed, dict):
        return parsed, result
    return None, result


def _lookup_map_raw(map_id, key_hex_bytes, bpftool_bin, run_command):
    cmd = ["sudo", bpftool_bin, "map", "lookup", "id", str(map_id), "key", "hex", *key_hex_bytes, "-j"]
    result = run_command(cmd, timeout=20)
    return result, cmd


def _value_from_lookup_output(lookup_result):
    stdout = str(lookup_result.get("stdout") or "")

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        formatted = parsed.get("formatted")
        if isinstance(formatted, dict) and isinstance(formatted.get("value"), int):
            return int(formatted.get("value"))

        value_field = parsed.get("value")
        if isinstance(value_field, int):
            return value_field
        if isinstance(value_field, str) and re.fullmatch(r"-?\d+", value_field.strip()):
            return int(value_field.strip())
        if isinstance(value_field, list) and value_field and all(isinstance(x, int) for x in value_field):
            value_bytes = bytes(value_field)
            return int.from_bytes(value_bytes, byteorder="little", signed=False)
        if isinstance(value_field, list) and value_field and all(isinstance(x, str) for x in value_field):
            normalized = []
            for item in value_field:
                s = item.strip().lower()
                if s.startswith("0x"):
                    s = s[2:]
                if not re.fullmatch(r"[0-9a-f]{1,2}", s):
                    normalized = []
                    break
                normalized.append(int(s, 16))
            if normalized:
                value_bytes = bytes(normalized)
                return int.from_bytes(value_bytes, byteorder="little", signed=False)

    m = re.search(r"value:\s*([0-9a-fA-F\s]+)", stdout)
    if m:
        parts = [p for p in m.group(1).split() if p]
        if parts and all(re.fullmatch(r"[0-9a-fA-F]{2}", p) for p in parts):
            value_bytes = bytes(int(p, 16) for p in parts)
            return int.from_bytes(value_bytes, byteorder="little", signed=False)

    m_num = re.search(r"value:\s*(-?\d+)", stdout)
    if m_num:
        return int(m_num.group(1))

    return None


def _mapctl_paths():
    utils_dir = Path(__file__).resolve().parents[2] / "ebpf" / "utils"
    return utils_dir, utils_dir / "mapctl"


def _read_pinned_map_u64(map_pin_path, key_u32, run_command):
    _, mapctl_bin = _mapctl_paths()
    cmd = ["sudo", str(mapctl_bin), "lookup-u64", "--map-pin", str(map_pin_path), "--key-u32", str(int(key_u32))]
    result = run_command(cmd, timeout=20)
    if result["returncode"] != 0 or result["timed_out"]:
        return None, result
    m = re.search(r"\"value\"\s*:\s*(\d+)", result.get("stdout") or "")
    if not m:
        return None, result
    return int(m.group(1)), result


def _write_pinned_map_u32(map_pin_path, key_u32, value_u32, run_command):
    _, mapctl_bin = _mapctl_paths()
    cmd = [
        "sudo",
        str(mapctl_bin),
        "update-u32",
        "--map-pin",
        str(map_pin_path),
        "--key-u32",
        str(int(key_u32)),
        "--value-u32",
        str(int(value_u32)),
    ]
    result = run_command(cmd, timeout=20)
    return result, cmd


def run_case_runtime_validation(case_dir, pin_path, bpftool_bin="bpftool", timeout=30, run_command=None):
    case_path = Path(case_dir)
    workload_path = case_path / "workload.sh"
    validator_path = case_path / "validator.yaml"
    runner = run_command or _default_run_command

    maps_dir = str(Path(str(pin_path) + "_maps"))
    base = {
        "stage": "runtime_test",
        "case_dir": str(case_path),
        "workload": str(workload_path),
        "validator": str(validator_path),
        "pin_path": str(pin_path),
        "maps_dir": maps_dir,
    }

    if not workload_path.exists():
        return {**base, "success": True, "skipped": True, "reason": "workload_not_found"}

    if not validator_path.exists():
        return {**base, "success": True, "skipped": True, "reason": "validator_not_found"}

    scheme_a = {
        "enabled": False,
        "cfg_map_pin": str(Path(maps_dir) / "cfg"),
        "workload_pid": None,
        "cfg_update_command": None,
        "cfg_update_stdout": None,
        "cfg_update_stderr": None,
        "cfg_update_timed_out": None,
        "cfg_update_returncode": None,
        "status": None,
    }
    cfg_pin = Path(maps_dir) / "cfg"
    proc = subprocess.Popen(
        ["bash", str(workload_path)],
        cwd=str(case_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    scheme_a["enabled"] = True
    scheme_a["workload_pid"] = proc.pid
    update_res, update_cmd = _write_pinned_map_u32(cfg_pin, 0, proc.pid, runner)
    scheme_a["cfg_update_command"] = update_cmd
    scheme_a["cfg_update_stdout"] = update_res.get("stdout")
    scheme_a["cfg_update_stderr"] = update_res.get("stderr")
    scheme_a["cfg_update_timed_out"] = update_res.get("timed_out")
    scheme_a["cfg_update_returncode"] = update_res.get("returncode")
    if update_res.get("returncode") != 0 or update_res.get("timed_out"):
        err_text = (update_res.get("stderr") or "") + "\n" + (update_res.get("stdout") or "")
        if "no such file" in err_text.lower() or "enoent" in err_text.lower():
            scheme_a["status"] = "skipped_missing_cfg"
            try:
                out, err = proc.communicate(timeout=timeout)
                workload_result = {
                    "command": ["bash", str(workload_path)],
                    "returncode": proc.returncode,
                    "stdout": out,
                    "stderr": err,
                    "timed_out": False,
                }
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception:
                    pass
                out, err = proc.communicate(timeout=2)
                workload_result = {
                    "command": ["bash", str(workload_path)],
                    "returncode": None,
                    "stdout": out,
                    "stderr": err,
                    "timed_out": True,
                }
        else:
            scheme_a["status"] = "failed"
            try:
                proc.kill()
            except Exception:
                pass
            out, err = proc.communicate(timeout=2)
            return {
                **base,
                "success": False,
                "skipped": False,
                "reason": "cfg_write_failed",
                "scheme_a": scheme_a,
                "cfg_map_pin": str(cfg_pin),
                "cfg_update_command": update_cmd,
                "cfg_update_stdout": update_res.get("stdout"),
                "cfg_update_stderr": update_res.get("stderr"),
                "workload_stdout": out,
                "workload_stderr": err,
            }
    if update_res.get("returncode") == 0 and not update_res.get("timed_out"):
        scheme_a["status"] = "applied"
        try:
            out, err = proc.communicate(timeout=timeout)
            workload_result = {
                "command": ["bash", str(workload_path)],
                "returncode": proc.returncode,
                "stdout": out,
                "stderr": err,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            out, err = proc.communicate(timeout=2)
            workload_result = {
                "command": ["bash", str(workload_path)],
                "returncode": None,
                "stdout": out,
                "stderr": err,
                "timed_out": True,
            }

    if workload_result["returncode"] != 0 or workload_result["timed_out"]:
        return {
            **base,
            "success": False,
            "skipped": False,
            "reason": "workload_failed",
            "scheme_a": scheme_a,
            "workload_command": workload_result["command"],
            "workload_stdout": workload_result["stdout"],
            "workload_stderr": workload_result["stderr"],
            "workload_timed_out": workload_result["timed_out"],
        }

    validator = _load_simple_yaml(validator_path)
    rule_type = str(validator.get("type") or "").strip().lower()
    map_name = validator.get("map")
    key = validator.get("key")
    expected = validator.get("value")

    if rule_type not in {"min", "eq"} or map_name is None or key is None or expected is None:
        return {**base, "success": False, "skipped": False, "reason": "validator_invalid", "scheme_a": scheme_a, "validator_payload": validator}

    map_pin_path = Path(maps_dir) / str(map_name)
    actual_value, mapctl_result = _read_pinned_map_u64(map_pin_path, key, runner)
    if actual_value is None:
        return {
            **base,
            "success": False,
            "skipped": False,
            "reason": "map_lookup_failed",
            "scheme_a": scheme_a,
            "map_pin_path": str(map_pin_path),
            "mapctl_command": mapctl_result.get("command"),
            "mapctl_stdout": mapctl_result.get("stdout"),
            "mapctl_stderr": mapctl_result.get("stderr"),
            "mapctl_timed_out": mapctl_result.get("timed_out"),
        }

    expected_int = int(expected)
    if rule_type == "min":
        compare_success = actual_value >= expected_int
        compare_expr = f">= {expected_int}"
    else:
        compare_success = actual_value == expected_int
        compare_expr = f"== {expected_int}"

    return {
        **base,
        "success": compare_success,
        "skipped": False,
        "reason": "validator_passed" if compare_success else "validator_mismatch",
        "validator_payload": validator,
        "scheme_a": scheme_a,
        "map_pin_path": str(map_pin_path),
        "actual_value": actual_value,
        "expected": compare_expr,
        "mapctl_command": mapctl_result.get("command"),
    }

