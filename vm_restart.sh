sudo -n rm -rf /sys/fs/bpf/ebpf_agent_* || true

KERNEL_VERSION="$(uname -r | cut -d. -f1,2)"
VENV_DIR="env/${KERNEL_VERSION}/venv"

source "${VENV_DIR}/bin/activate"

# python3 main.py "$@"
# python3 main.py feature/isa_upgrade_incompatible "$@"
# python3 main.py feature/map_type_unsupported "$@"
python3 main.py helper_func/helper_absent "$@"