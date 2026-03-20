# 配置python环境
KERNEL_VERSION="$(uname -r | cut -d. -f1,2)"
VENV_DIR="env/${KERNEL_VERSION}/venv"

if [ ! -d "${VENV_DIR}" ]; then
    python3 -m venv "${VENV_DIR}"
fi

source "${VENV_DIR}/bin/activate"
pip install -r requirements.txt