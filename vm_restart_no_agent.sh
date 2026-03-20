sudo -n rm -rf /sys/fs/bpf/ebpf_agent_* || true

KERNEL_VERSION="$(uname -r | cut -d. -f1,2)"
VENV_DIR="env/${KERNEL_VERSION}/venv"

source "${VENV_DIR}/bin/activate"

python3 main.py --no-agent
# python3 main.py kernel_struct