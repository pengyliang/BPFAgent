"""Deployment executor (legacy compatibility layer)."""

from __future__ import annotations

from src.util.deploy.attach import attach_bpf_program, infer_attach_plan
from src.util.deploy.commands import run_command as _run_command
from src.util.deploy.compile import compile_bpf_program, maybe_inject_task_tgid_offset as _maybe_inject_task_tgid_offset
from src.util.deploy.detach import detach_bpf_program
from src.util.deploy.load import (
    load_bpf_program_bpftool as load_bpf_program,
    load_bpf_program_with_libbpf_loader,
    safe_remove_tree as _safe_remove_tree,
    safe_unpin as _safe_unpin,
    safe_unpin_links_flat as _safe_unpin_links_flat,
    start_libbpf_loader_daemon as _start_libbpf_loader_daemon,
)
from src.util.deploy.pipeline import deploy_bpf_program, make_deploy_result_summary, save_deploy_report
from src.util.deploy.verifier import parse_verifier_log

__all__ = [
    "_maybe_inject_task_tgid_offset",
    "_run_command",
    "_safe_remove_tree",
    "_safe_unpin",
    "_safe_unpin_links_flat",
    "_start_libbpf_loader_daemon",
    "attach_bpf_program",
    "compile_bpf_program",
    "deploy_bpf_program",
    "detach_bpf_program",
    "infer_attach_plan",
    "load_bpf_program",
    "load_bpf_program_with_libbpf_loader",
    "make_deploy_result_summary",
    "parse_verifier_log",
    "save_deploy_report",
]

