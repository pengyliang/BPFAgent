sudo -n rm -rf /sys/fs/bpf/ebpf_agent_* || true
source venv/bin/activate
# python3 main.py "$@"
# source venv/bin/activate && python3 main.py kernel_struct
python3 main.py kernel_struct/field_renamed "$@"
