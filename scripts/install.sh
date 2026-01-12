#!/bin/bash
#
# EdgeLink 一键安装脚本
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --debug
#   curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --client-only
#   curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --controller-only
#

set -e

# 配置
REPO="hyird/EdgeLink"
RELEASE_TAG="autobuild"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edgelink"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/tags/${RELEASE_TAG}"
GITHUB_DOWNLOAD="https://github.com/${REPO}/releases/download/${RELEASE_TAG}"

# 默认选项
BUILD_TYPE="release"
INSTALL_CLIENT=true
INSTALL_CONTROLLER=true

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
EdgeLink 安装脚本

用法: install.sh [选项]

选项:
  --release         安装 Release 版本 (默认)
  --debug           安装 Debug 版本
  --client-only     仅安装客户端
  --controller-only 仅安装控制器
  --uninstall       卸载 EdgeLink
  -h, --help        显示帮助信息

示例:
  # 安装 Release 版本（客户端 + 控制器）
  ./install.sh

  # 安装 Debug 版本
  ./install.sh --debug

  # 仅安装客户端 Release 版本
  ./install.sh --client-only

  # 安装 Debug 版本的控制器
  ./install.sh --debug --controller-only

  # 卸载
  ./install.sh --uninstall

EOF
}

# 解析参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --release)
                BUILD_TYPE="release"
                shift
                ;;
            --debug)
                BUILD_TYPE="debug"
                shift
                ;;
            --client-only)
                INSTALL_CLIENT=true
                INSTALL_CONTROLLER=false
                shift
                ;;
            --controller-only)
                INSTALL_CLIENT=false
                INSTALL_CONTROLLER=true
                shift
                ;;
            --uninstall)
                do_uninstall
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 设置 sudo 命令（如果不是 root 则使用 sudo）
setup_sudo() {
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo &> /dev/null; then
            SUDO="sudo"
            log_info "将使用 sudo 执行特权操作"
        else
            log_error "需要 root 权限，请安装 sudo 或以 root 用户运行"
            exit 1
        fi
    else
        SUDO=""
    fi
}

# 检查系统架构
check_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            log_error "暂不支持 ARM64 架构"
            exit 1
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    log_info "检测到架构: $ARCH"
}

# 检查依赖
check_deps() {
    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "缺少依赖: ${missing[*]}"
        log_info "请先安装: apt install ${missing[*]} 或 yum install ${missing[*]}"
        exit 1
    fi
}

# 下载文件
download_file() {
    local url=$1
    local dest=$2
    local name=$3

    log_info "下载 ${name}..."
    if curl -fsSL -o "$dest" "$url"; then
        log_success "${name} 下载完成"
    else
        log_error "${name} 下载失败"
        return 1
    fi
}

# 安装二进制文件
install_binary() {
    local name=$1
    local url="${GITHUB_DOWNLOAD}/edgelink-${name}-linux-${ARCH}-${BUILD_TYPE}"
    local dest="${BIN_DIR}/edgelink-${name}"
    local tmp_file=$(mktemp)

    if download_file "$url" "$tmp_file" "edgelink-${name}"; then
        $SUDO mv "$tmp_file" "$dest"
        $SUDO chmod +x "$dest"
        log_success "已安装 ${dest}"
    else
        rm -f "$tmp_file"
        return 1
    fi
}

# 创建配置目录
setup_config_dir() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        log_info "创建配置目录: ${CONFIG_DIR}"
        $SUDO mkdir -p "$CONFIG_DIR"
    fi

    # 创建示例配置文件（如果不存在）
    if [[ ! -f "${CONFIG_DIR}/client.toml" ]]; then
        $SUDO tee "${CONFIG_DIR}/client.toml.example" > /dev/null << 'EOF'
# EdgeLink 客户端配置示例
# 复制此文件为 client.toml 并修改

[controller]
# 控制器地址
url = "wss://controller.example.com:8443"

[auth]
# 认证密钥
authkey = "your-auth-key-here"

[tun]
# TUN 设备名称
name = "edgelink0"

[p2p]
# 是否启用 P2P 直连
enabled = true
# P2P 绑定端口 (0 = 随机)
bind_port = 0

[log]
# 日志级别: trace, debug, info, warn, error
level = "info"
EOF
        log_info "已创建示例配置: ${CONFIG_DIR}/client.toml.example"
    fi

    if [[ ! -f "${CONFIG_DIR}/controller.toml" ]]; then
        $SUDO tee "${CONFIG_DIR}/controller.toml.example" > /dev/null << 'EOF'
# EdgeLink 控制器配置示例
# 复制此文件为 controller.toml 并修改

[server]
# 监听地址
listen = "0.0.0.0"
# 监听端口
port = 8443

[tls]
# TLS 证书路径
cert = "/etc/edgelink/server.crt"
key = "/etc/edgelink/server.key"

[database]
# 数据库路径
path = "/var/lib/edgelink/edgelink.db"

[jwt]
# JWT 密钥（请修改为随机字符串）
secret = "change-me-to-random-string"

[log]
# 日志级别: trace, debug, info, warn, error
level = "info"
EOF
        log_info "已创建示例配置: ${CONFIG_DIR}/controller.toml.example"
    fi
}

# 创建 systemd 服务
setup_systemd() {
    if [[ ! -d /etc/systemd/system ]]; then
        log_warn "未检测到 systemd，跳过服务安装"
        return
    fi

    if $INSTALL_CLIENT; then
        $SUDO tee /etc/systemd/system/edgelink-client.service > /dev/null << EOF
[Unit]
Description=EdgeLink Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/edgelink-client --config ${CONFIG_DIR}/client.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        log_success "已创建 systemd 服务: edgelink-client.service"
    fi

    if $INSTALL_CONTROLLER; then
        $SUDO tee /etc/systemd/system/edgelink-controller.service > /dev/null << EOF
[Unit]
Description=EdgeLink Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/edgelink-controller --config ${CONFIG_DIR}/controller.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        log_success "已创建 systemd 服务: edgelink-controller.service"
    fi

    $SUDO systemctl daemon-reload
}

# 卸载
do_uninstall() {
    setup_sudo

    log_info "正在卸载 EdgeLink..."

    # 停止服务
    if $SUDO systemctl is-active --quiet edgelink-client 2>/dev/null; then
        $SUDO systemctl stop edgelink-client
    fi
    if $SUDO systemctl is-active --quiet edgelink-controller 2>/dev/null; then
        $SUDO systemctl stop edgelink-controller
    fi

    # 禁用服务
    $SUDO systemctl disable edgelink-client 2>/dev/null || true
    $SUDO systemctl disable edgelink-controller 2>/dev/null || true

    # 删除服务文件
    $SUDO rm -f /etc/systemd/system/edgelink-client.service
    $SUDO rm -f /etc/systemd/system/edgelink-controller.service
    $SUDO systemctl daemon-reload

    # 删除二进制文件
    $SUDO rm -f "${BIN_DIR}/edgelink-client"
    $SUDO rm -f "${BIN_DIR}/edgelink-controller"

    log_success "EdgeLink 已卸载"
    log_warn "配置目录 ${CONFIG_DIR} 未删除，如需删除请手动执行: sudo rm -rf ${CONFIG_DIR}"
}

# 显示安装信息
show_install_info() {
    echo ""
    echo "======================================"
    echo -e "${GREEN}EdgeLink 安装完成!${NC}"
    echo "======================================"
    echo ""
    echo "版本: ${BUILD_TYPE}"
    echo "二进制目录: ${BIN_DIR}"
    echo "配置目录: ${CONFIG_DIR}"
    echo ""

    if $INSTALL_CLIENT; then
        echo "客户端:"
        echo "  配置文件: ${CONFIG_DIR}/client.toml"
        echo "  启动服务: sudo systemctl start edgelink-client"
        echo "  开机启动: sudo systemctl enable edgelink-client"
        echo ""
    fi

    if $INSTALL_CONTROLLER; then
        echo "控制器:"
        echo "  配置文件: ${CONFIG_DIR}/controller.toml"
        echo "  启动服务: sudo systemctl start edgelink-controller"
        echo "  开机启动: sudo systemctl enable edgelink-controller"
        echo ""
    fi

    echo "下一步:"
    echo "  1. 编辑配置文件"
    echo "  2. 启动服务"
    echo ""
}

# 主函数
main() {
    echo ""
    echo "======================================"
    echo "     EdgeLink 安装脚本"
    echo "======================================"
    echo ""

    parse_args "$@"
    setup_sudo
    check_arch
    check_deps

    log_info "构建类型: ${BUILD_TYPE}"
    log_info "安装客户端: ${INSTALL_CLIENT}"
    log_info "安装控制器: ${INSTALL_CONTROLLER}"
    echo ""

    # 安装二进制文件
    if $INSTALL_CLIENT; then
        install_binary "client" || exit 1
    fi

    if $INSTALL_CONTROLLER; then
        install_binary "controller" || exit 1
    fi

    # 设置配置和服务
    setup_config_dir
    setup_systemd

    show_install_info
}

main "$@"
