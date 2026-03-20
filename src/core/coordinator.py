from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.util.deploy.load import safe_remove_tree, terminate_loader_daemon
from src.util.stages.compiler_tool import CompilerTool
from src.util.stages.detach_tool import DetachTool
from src.util.stages.load_attacher_tool import LoadAttacherTool, LoadBackend
from src.util.stages.static_check_tool import StaticCheckTool
from src.util.stages.tester_tool import TesterTool


def stable_error_signature(deploy_report: Dict[str, Any]) -> str:
    if not isinstance(deploy_report, dict):
        return "unknown"
    stage = str(deploy_report.get("stage") or "unknown")
    if stage == "compile_failed":
        compile_step = deploy_report.get("compile") or {}
        if isinstance(compile_step, dict):
            raw = ((compile_step.get("stderr") or "") + "\n" + (compile_step.get("stdout") or "")).strip()
            for ln in raw.splitlines():
                low = ln.lower()
                if "fatal error:" in low or "error:" in low:
                    cleaned = " ".join(ln.strip().split())
                    return f"{stage}:{cleaned[:160]}".strip(":") or "unknown"
        return f"{stage}:compile_error"
    load = deploy_report.get("load") or {}
    verifier = (load.get("verifier") or {}) if isinstance(load, dict) else {}
    primary = verifier.get("primary_error_type") or ""
    return f"{stage}:{primary}".strip(":") or "unknown"


@dataclass
class CoordinatorConfig:
    max_retries: int = 1
    loader_backend_order: Tuple[LoadBackend, ...] = ("libbpf_daemon", "libbpf_once", "bpftool")
    enable_agent: bool = True
    agent_max_patches: int = 2


@dataclass
class Coordinator:
    """Deterministic policy layer."""

    static_tool: StaticCheckTool = field(default_factory=StaticCheckTool)
    compiler_tool: CompilerTool = field(default_factory=CompilerTool)
    load_attacher_tool: LoadAttacherTool = field(default_factory=LoadAttacherTool)
    tester_tool: TesterTool = field(default_factory=TesterTool)
    detach_tool: DetachTool = field(default_factory=DetachTool)
    config: CoordinatorConfig = field(default_factory=CoordinatorConfig)
    llm: Optional[Any] = None

    def choose_loader_backend(self, *, attempt: int, last_error_sig: Optional[str]) -> LoadBackend:
        # TEMP: disable backend rotation; always use libbpf daemon loader.
        # Keep loader_backend_order for future re-enable/debug.
        return "libbpf_daemon"

    def run_static_check(
        self,
        *,
        summaries: List[Dict[str, Any]],
        kernel_profile: Dict[str, Any],
        output_path: Optional[str],
    ) -> Dict[str, Any]:
        return self.static_tool.run(
            summaries=summaries,
            kernel_profile=kernel_profile,
            output_path=output_path,
        ).payload

    def run_compile(
        self,
        *,
        source_file: str,
        object_file: str,
        vmlinux_header_dir: Optional[str],
    ) -> Dict[str, Any]:
        res = self.compiler_tool.run(
            source_file=source_file,
            object_file=object_file,
            vmlinux_header_dir=vmlinux_header_dir,
        )
        payload = res.payload or {}
        payload.setdefault("success", bool(res.success) if "success" not in payload else payload.get("success"))
        return payload

    def run_load_attach(
        self,
        *,
        source_file: str,
        object_file: str,
        pin_path: str,
        program_type: Optional[str],
        backend: LoadBackend,
    ) -> Dict[str, Any]:
        res = self.load_attacher_tool.run(
            source_file=source_file,
            object_file=object_file,
            pin_path=pin_path,
            program_type=program_type,
            backend=backend,
        )
        return res.payload or {}

    def run_runtime_test(
        self,
        *,
        source_file: str,
        pin_path: str,
        attach_report: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if isinstance(attach_report, dict) and attach_report.get("success") and attach_report.get("attached"):
            res = self.tester_tool.run(source_file=source_file, pin_path=pin_path)
            payload = res.payload or {}
            payload.setdefault("success", bool(res.success) if "success" not in payload else payload.get("success"))
            return payload
        return {
            "success": True,
            "stage": "runtime_test",
            "skipped": True,
            "reason": "attach_not_active",
            "case_dir": str(Path(source_file).parent),
            "pin_path": str(pin_path),
        }

    def run_detach(
        self,
        *,
        backend: LoadBackend,
        pin_path: str,
        load_report: Optional[Dict[str, Any]],
        attach_report: Optional[Dict[str, Any]],
        proc: Any = None,
    ) -> Dict[str, Any]:
        if backend == "libbpf_daemon":
            terminate_loader_daemon(proc)
            safe_remove_tree(str(pin_path) + "_maps")
            return {
                "success": True,
                "stage": "detach",
                "detached": True,
                "skipped": False,
                "reason": "loader_terminated",
                "pin_path": pin_path,
                "pid": (load_report or {}).get("pid") if isinstance(load_report, dict) else None,
            }
        res = self.detach_tool.run(pin_path=pin_path, attach_result=attach_report or {})
        payload = res.payload or {}
        payload.setdefault("success", bool(res.success) if "success" not in payload else payload.get("success"))
        return payload

    def classify_deploy_stage(
        self,
        *,
        compile_report: Optional[Dict[str, Any]],
        load_report: Optional[Dict[str, Any]],
        attach_report: Optional[Dict[str, Any]],
        runtime_report: Optional[Dict[str, Any]],
        detach_report: Optional[Dict[str, Any]],
        static_report: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        # 有 static_check 落盘内容时，以其 success 为准（与 workflow deploy 语义一致）
        if isinstance(static_report, dict) and static_report and not bool(static_report.get("success")):
            return False, "static_check_failed"
        if not (isinstance(compile_report, dict) and compile_report.get("success")):
            return False, "compile_failed"
        if (
            isinstance(attach_report, dict)
            and (not attach_report.get("success"))
            and attach_report.get("reason") == "libbpf_loader_attach_failed"
        ):
            return False, "attach_failed"
        if not (isinstance(load_report, dict) and load_report.get("success")):
            return False, "load_failed"
        if not (isinstance(attach_report, dict) and attach_report.get("success")):
            return False, "attach_failed"
        if not (isinstance(runtime_report, dict) and runtime_report.get("success")):
            return False, "runtime_test_failed"
        return True, "success"

