#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法:
  ./move_files.sh "<experiments_subpath>" [version1 version2 ...] [--overwrite] [--dry-run]

示例:
  ./move_files.sh "不同LLM对比/deepseek-v3.2"
  ./move_files.sh "不同LLM对比/deepseek-v3.2" 5.4 5.15
  ./move_files.sh "不同LLM对比/deepseek-v3.2" 5.4 --overwrite

说明:
  - records（即 reports 目录）会从 output/<version>/log/reports 复制到
    experiments/<experiments_subpath>/<version>/reports
  - 所有原始 log 会从 output/<version>/log 复制到
    experiments/<experiments_subpath>/original_logs/<version>/log
  - 最终目录结构参考: experiments/LLM/deepseek-v3.2
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
output_root="${repo_root}/output"
experiments_root="${repo_root}/experiments"

overwrite=0
dry_run=0
target=""
versions=()

for arg in "$@"; do
  case "${arg}" in
    -h|--help)
      usage
      exit 0
      ;;
    --overwrite)
      overwrite=1
      ;;
    --dry-run)
      dry_run=1
      ;;
    *)
      if [[ -z "${target}" ]]; then
        target="${arg}"
      else
        versions+=("${arg}")
      fi
      ;;
  esac
done

if [[ -z "${target}" ]]; then
  echo "[ERROR] target 参数不能为空。" >&2
  usage >&2
  exit 1
fi

if [[ ! -d "${output_root}" ]]; then
  echo "[ERROR] output_root 不存在: ${output_root}" >&2
  exit 1
fi
if [[ ! -d "${experiments_root}" ]]; then
  echo "[ERROR] experiments_root 不存在: ${experiments_root}" >&2
  exit 1
fi

is_version_dir() {
  local base="$1"
  # e.g. 4.19, 5.4, 5.15, 6.6
  [[ "${base}" =~ ^[0-9]+\.[0-9]+([.][0-9]+)?$ ]] || [[ "${base}" =~ ^[0-9]+\.[0-9]+$ ]]
}

collect_versions() {
  local out=()
  for d in "${output_root}"/*; do
    [[ -d "${d}" ]] || continue
    base="$(basename "${d}")"
    if is_version_dir "${base}"; then
      out+=("${base}")
    fi
  done
  # sort (numeric-ish is overkill; just lex sort is fine for e.g. 5.4/5.15)
  printf "%s\n" "${out[@]}" | sort
}

versions_to_process=()
if [[ "${#versions[@]}" -gt 0 ]]; then
  versions_to_process=("${versions[@]}")
else
  while IFS= read -r v; do
    [[ -n "${v}" ]] && versions_to_process+=("${v}")
  done < <(collect_versions)
fi

if [[ "${#versions_to_process[@]}" -eq 0 ]]; then
  echo "[WARN] 没有要处理的版本。" >&2
  exit 0
fi

do_move_reports_for_version() {
  local version="$1"
  local src_log="${output_root}/${version}/log"
  local src_reports="${src_log}/reports"
  local dst_reports="${experiments_root}/${target}/${version}/reports"
  local dst_log="${experiments_root}/${target}/original_logs/${version}/log"

  if [[ ! -d "${src_log}" ]]; then
    echo "[SKIP] ${version}: src log 不存在: ${src_log}"
    return
  fi

  if [[ ! -d "${src_reports}" ]]; then
    echo "[WARN] ${version}: reports 不存在，将仅复制 log: ${src_reports}"
  fi

  local do_copy_reports=1
  local do_copy_log=1

  if [[ -e "${dst_reports}" ]]; then
    if [[ "${overwrite}" -eq 0 ]]; then
      echo "[SKIP] ${version}: reports dst 已存在: ${dst_reports} (use --overwrite to replace)"
      do_copy_reports=0
    else
      echo "[OVERWRITE] ${version}: rm -rf ${dst_reports}"
      if [[ "${dry_run}" -eq 0 ]]; then
        rm -rf "${dst_reports}"
      fi
    fi
  fi

  if [[ -e "${dst_log}" ]]; then
    if [[ "${overwrite}" -eq 0 ]]; then
      echo "[SKIP] ${version}: log dst 已存在: ${dst_log} (use --overwrite to replace)"
      do_copy_log=0
    else
      echo "[OVERWRITE] ${version}: rm -rf ${dst_log}"
      if [[ "${dry_run}" -eq 0 ]]; then
        rm -rf "${dst_log}"
      fi
    fi
  fi

  if [[ "${do_copy_reports}" -eq 1 && -d "${src_reports}" ]]; then
    echo "[COPY] ${version}: ${src_reports} -> ${dst_reports}"
  fi
  if [[ "${do_copy_log}" -eq 1 ]]; then
    echo "[COPY] ${version}: ${src_log} -> ${dst_log}"
  fi
  if [[ "${dry_run}" -eq 0 ]]; then
    if [[ "${do_copy_reports}" -eq 1 && -d "${src_reports}" ]]; then
      mkdir -p "$(dirname "${dst_reports}")"
      cp -a "${src_reports}" "${dst_reports}"
    fi
    if [[ "${do_copy_log}" -eq 1 ]]; then
      mkdir -p "$(dirname "${dst_log}")"
      cp -a "${src_log}" "${dst_log}"
    fi
  fi
}

for v in "${versions_to_process[@]}"; do
  do_move_reports_for_version "${v}"
done

echo "Done. target=${target} overwrite=${overwrite} dry_run=${dry_run}"