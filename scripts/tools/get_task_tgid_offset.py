#!/usr/bin/env python3
"""
在 6.6 内核 VM 中运行，从 BTF 解析 task_struct.tgid 的字节偏移，用于 field_offset_change 用例。

用法（在 6.6 虚拟机内）:
  sudo bpftool btf dump file /sys/kernel/btf/vmlinux format raw -j 2>/dev/null | python3 scripts/tools/get_task_tgid_offset.py

或先生成文件再解析:
  sudo bpftool btf dump file /sys/kernel/btf/vmlinux format raw -j -p > /tmp/btf.json
  python3 scripts/tools/get_task_tgid_offset.py /tmp/btf.json
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def get_types(btf):
    """从 bpftool 的 JSON 里取出类型列表。根可能是 list 或 dict。"""
    if isinstance(btf, list):
        return btf
    if isinstance(btf, dict):
        # 常见：{"types": [...]} 或根就是 types 的包装
        if "types" in btf:
            return btf["types"]
        # 若根 dict 的某个 value 是 list，且元素是 type 对象，用第一个这样的 list
        for v in btf.values():
            if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                return v
    return []


def main():
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        text = path.read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    try:
        btf = json.loads(text)
    except json.JSONDecodeError as e:
        print("JSON 解析失败:", e, file=sys.stderr)
        sys.exit(1)

    types = get_types(btf)
    if not types:
        print("未找到 BTF 类型列表，根结构示例:", type(btf), list(btf)[:5] if isinstance(btf, dict) else "list len=" + str(len(btf)), file=sys.stderr)
        sys.exit(1)

    for t in types:
        if not isinstance(t, dict):
            continue
        if t.get("kind") != "struct" and t.get("kind") != "STRUCT":
            continue
        if t.get("name") != "task_struct":
            continue
        members = t.get("members") or t.get("Members") or []
        for m in members:
            if not isinstance(m, dict):
                continue
            name = m.get("name") or m.get("Name")
            if name != "tgid":
                continue
            # bit_offset 或 bits_offset
            bit_off = m.get("bit_offset") or m.get("bits_offset") or m.get("bitOffset")
            if bit_off is None:
                print("tgid 无 bit_offset 字段，member 键:", list(m.keys()), file=sys.stderr)
                sys.exit(1)
            try:
                bit_off = int(bit_off)
            except (TypeError, ValueError):
                print("bit_offset 非整数:", bit_off, file=sys.stderr)
                sys.exit(1)
            byte_off = bit_off // 8
            print("task_struct.tgid  bit_offset =", bit_off, "  byte_offset =", byte_off, "(0x%x)" % byte_off)
            print()
            print("在 field_offset_change.bpf.c 中改为:")
            print("#define TASK_TGID_OFFSET_66 0x%x" % byte_off)
            return
        print("task_struct 中未找到 member tgid，members 数量:", len(members), file=sys.stderr)
        sys.exit(1)

    print("未找到 struct task_struct", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
