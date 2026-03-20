"""Run compile/load deployment and emit structured deploy report."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.util.deploy.executor import deploy_bpf_program, make_deploy_result_summary, save_deploy_report


if __name__ == "__main__":
    data_dir = REPO_ROOT / "tests" / "data"
    logs_dir = REPO_ROOT / "tests" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    sources = sorted(data_dir.glob("*.bpf.c"))
    if not sources:
        print("No .bpf.c source files found under tests/data")
        raise SystemExit(1)

    per_file_reports = []
    success_count = 0

    for source in sources:
        stem = source.name.replace(".bpf.c", "")
        object_path = logs_dir / f"{stem}.bpf.o"
        pin_path = f"/sys/fs/bpf/ebpf_agent_{stem}"
        file_report_path = logs_dir / f"deploy_result_{stem}.json"
        compile_report_path = logs_dir / f"compile_result_{stem}.json"
        load_report_path = logs_dir / f"load_result_{stem}.json"
        attach_report_path = logs_dir / f"attach_result_{stem}.json"
        runtime_report_path = logs_dir / f"runtime_result_{stem}.json"
        detach_report_path = logs_dir / f"detach_result_{stem}.json"

        report = deploy_bpf_program(
            source_file=str(source),
            pin_path=pin_path,
            object_file=str(object_path),
            program_type="kprobe",
        )
        save_deploy_report(make_deploy_result_summary(report), str(file_report_path))
        save_deploy_report(report.get("compile"), str(compile_report_path))
        save_deploy_report(report.get("load"), str(load_report_path))
        save_deploy_report(report.get("attach"), str(attach_report_path))
        save_deploy_report(report.get("runtime"), str(runtime_report_path))
        save_deploy_report(report.get("detach"), str(detach_report_path))

        per_file_reports.append(
            {
                "source": str(source),
                "report": str(file_report_path.relative_to(REPO_ROOT)),
                "success": report["success"],
                "stage": report["stage"],
                "compile_report": str(compile_report_path.relative_to(REPO_ROOT)),
                "load_report": str(load_report_path.relative_to(REPO_ROOT)),
                "attach_report": str(attach_report_path.relative_to(REPO_ROOT)),
                "runtime_report": str(runtime_report_path.relative_to(REPO_ROOT)),
                "detach_report": str(detach_report_path.relative_to(REPO_ROOT)),
            }
        )
        if report["success"]:
            success_count += 1

        print(
            f"Deploy {source.name}: success={report['success']} "
            f"stage={report['stage']} report={file_report_path.relative_to(REPO_ROOT)}"
        )

    aggregate = {
        "total_files": len(per_file_reports),
        "success_count": success_count,
        "failure_count": len(per_file_reports) - success_count,
        "results": per_file_reports,
    }
    aggregate_path = logs_dir / "deploy_report.json"
    save_deploy_report(aggregate, str(aggregate_path))
    print(
        "Deploy summary:",
        f"total={aggregate['total_files']}",
        f"success={aggregate['success_count']}",
        f"failed={aggregate['failure_count']}",
        f"report={aggregate_path.relative_to(REPO_ROOT)}",
    )
