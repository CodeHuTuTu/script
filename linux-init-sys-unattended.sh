#!/bin/bash

#===============================================================================
# Debian 12 系统初始化配置脚本
# 功能：系统更新、Docker安装、用户管理、SSH配置、安全加固、网络优化等
# 用法（交互）:   bash linux-init-sys.sh
# 用法（无人值守）: 运行脚本后在菜单选择 u
#===============================================================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        echo "请使用: sudo bash $0"
        exit 1
    fi
}

# 确认提示
confirm() {
    local prompt="$1"
    local default="${2:-n}"

    if [[ $default == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -p "$prompt" response
    response=${response:-$default}

    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

#===============================================================================
# 1. 系统更新
#===============================================================================
update_system() {
    log_step "系统更新"

    log_info "更新软件包列表..."
    apt update

    log_info "升级已安装的软件包..."
    apt upgrade -y

    log_info "升级系统（包括内核）..."
    apt full-upgrade -y

    log_info "清理不需要的软件包..."
    apt autoremove -y
    apt autoclean

    log_info "系统更新完成！"
}

#===============================================================================
# 2. 安装 Docker（官方源）
#===============================================================================
install_docker() {
    log_step "安装 Docker"

    # 检查是否已安装
    if command -v docker &> /dev/null; then
        local version
        version=$(docker --version)
        log_warn "Docker 已安装: $version"
        if ! confirm "是否重新安装？"; then
            return
        fi
    fi

    log_info "安装依赖包..."
    apt install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    log_info "添加 Docker 官方 GPG 密钥..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    log_info "添加 Docker 官方软件源..."
    echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
       $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    log_info "更新软件包列表..."
    apt update

    log_info "安装 Docker Engine, containerd 和 Docker Compose..."
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    log_info "启动并启用 Docker 服务..."
    systemctl start docker
    systemctl enable docker

    log_info "验证 Docker 安装..."
    docker --version
    docker compose version

    log_info "Docker 安装完成！"
}

#===============================================================================
# 3. 新建用户（交互）
#===============================================================================
create_user() {
    log_step "新建用户"

    read -p "请输入新用户名: " username

    if [[ -z "$username" ]]; then
        log_error "用户名不能为空"
        return 1
    fi

    # 检查用户是否已存在
    if id "$username" &>/dev/null; then
        log_warn "用户 $username 已存在"
        return 1
    fi

    log_info "创建用户 $username..."
    useradd -m -s /bin/bash "$username"

    log_info "设置用户密码..."
    passwd "$username"

    # 询问是否添加 sudo 权限
    if confirm "是否为用户 $username 添加 sudo 权限？" "y"; then
        usermod -aG sudo "$username"
        log_info "已将用户添加到 sudo 组"
    fi

    # 询问是否添加到 docker 组
    if command -v docker &> /dev/null; then
        if confirm "是否允许用户 $username 使用 Docker（无需 sudo）？"; then
            usermod -aG docker "$username"
            log_info "已将用户添加到 docker 组"
        fi
    fi

    log_info "用户 $username 创建完成！"
}

#===============================================================================
# 4. 添加 SSH 密钥（交互）
#===============================================================================
add_ssh_key() {
    log_step "添加 SSH 密钥"

    read -p "请输入用户名（为该用户添加 SSH 密钥）: " username

    if [[ -z "$username" ]]; then
        log_error "用户名不能为空"
        return 1
    fi

    if ! id "$username" &>/dev/null; then
        log_error "用户 $username 不存在"
        return 1
    fi

    local user_home
    user_home=$(eval echo "~$username")
    local ssh_dir="$user_home/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    log_info "为用户 $username 配置 SSH 密钥..."

    # 创建 .ssh 目录
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        log_info "已创建目录: $ssh_dir"
    fi

    # 获取公钥
    echo -e "\n${YELLOW}请粘贴 SSH 公钥内容（粘贴后按 Enter，然后输入 END 或 end 并按 Enter 结束）：${NC}"
    echo "----------------------------------------"

    local pubkey=""
    local line
    while IFS= read -r line; do
        # 忽略大小写比较
        if [[ "${line,,}" == "end" ]]; then
            break
        fi
        pubkey+="$line"$'\n'
    done

    if [[ -z "$pubkey" ]]; then
        log_error "未输入公钥内容"
        return 1
    fi

    # 添加公钥到 authorized_keys
    echo "$pubkey" >> "$auth_keys"

    # 设置正确的权限
    chown -R "$username:$username" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_keys"

    log_info "权限设置："
    echo "  $ssh_dir: 700"
    echo "  $auth_keys: 600"
    echo "  所有者: $username:$username"

    log_info "SSH 密钥添加完成！"

    # 显示 authorized_keys 的密钥数量
    local key_count
    key_count=$(grep -c "ssh-" "$auth_keys" 2>/dev/null || echo "0")
    log_info "当前 authorized_keys 中有 $key_count 个密钥"
}

#===============================================================================
# 5. 安装常用工具（交互）
#===============================================================================
install_common_tools() {
    log_step "安装常用工具"

    local tools=(
        "vim"           # 文本编辑器
        "git"           # 版本控制
        "curl"          # HTTP 工具
        "wget"          # 下载工具
        "htop"          # 进程查看
        "net-tools"     # 网络工具（ifconfig等）
        "tree"          # 目录树显示
        "unzip"         # 解压工具
        "zip"           # 压缩工具
        "tmux"          # 终端复用
        "ncdu"          # 磁盘使用分析
        "iotop"         # IO 监控
        "sysstat"       # 系统性能工具
        "lsof"          # 查看打开的文件
        "dnsutils"      # DNS 工具（dig, nslookup）
        "tcpdump"       # 网络抓包
        "sudo"          # sudo
    )

    log_info "将安装以下工具："
    for tool in "${tools[@]}"; do
        echo "  - $tool"
    done

    if ! confirm "确认安装？" "y"; then
        return
    fi

    log_info "开始安装..."
    apt install -y "${tools[@]}"

    log_info "常用工具安装完成！"
}

#===============================================================================
# 无人值守：安装常用工具（不询问）
#===============================================================================
install_common_tools_unattended() {
    log_step "无人值守：安装常用工具"
    local tools=(
        "vim" "git" "curl" "wget" "htop" "net-tools" "tree" "unzip"
        "zip" "tmux" "ncdu" "iotop" "sysstat" "lsof" "dnsutils" "tcpdump" "sudo"
    )
    log_info "将安装以下工具（无人值守，自动确认）："
    for tool in "${tools[@]}"; do
        echo "  - $tool"
    done
    apt install -y "${tools[@]}"
    log_info "无人值守：常用工具安装完成"
}

#===============================================================================
# 6. 配置时区
#===============================================================================
configure_timezone() {
    log_step "配置时区"

    local timezone="Asia/Shanghai"
    local current_tz
    current_tz=$(timedatectl show -p Timezone --value)

    log_info "当前时区: $current_tz"
    log_info "将设置为: $timezone"

    if ! confirm "确认修改时区？" "y"; then
        return
    fi

    timedatectl set-timezone "$timezone"

    log_info "时区设置完成！"
    log_info "当前时间: $(date)"
}

#===============================================================================
# 7. 配置 UFW 防火墙（交互）
#===============================================================================
configure_ufw() {
    log_step "配置 UFW 防火墙"

    # 安装 UFW
    if ! command -v ufw &> /dev/null; then
        log_info "安装 UFW..."
        apt install -y ufw
    fi

    log_warn "配置防火墙前请确保至少开放一个 SSH 端口，否则可能失去连接！"

    # 获取当前 SSH 端口
    local current_ssh_port
    current_ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    current_ssh_port=${current_ssh_port:-22}

    log_info "当前 SSH 端口: $current_ssh_port"

    read -p "请输入要开放的 SSH 端口 [默认: $current_ssh_port]: " ssh_port
    ssh_port=${ssh_port:-$current_ssh_port}

    log_info "配置防火墙规则..."

    # 处理默认策略
    local ufw_status_line
    ufw_status_line=$(ufw status 2>/dev/null | head -n1 || echo "Status: inactive")
    if echo "$ufw_status_line" | grep -q "inactive"; then
        log_info "UFW 当前未启用，将设置默认策略为：拒绝入站 / 允许出站"
        ufw default deny incoming
        ufw default allow outgoing
    else
        log_warn "UFW 当前已启用，可能已有默认策略"
        if confirm "是否重置默认策略为：拒绝入站 / 允许出站？"; then
            ufw default deny incoming
            ufw default allow outgoing
        else
            log_info "保留现有默认策略"
        fi
    fi

    # 开放 SSH 端口
    log_info "开放 SSH 端口: $ssh_port"
    ufw allow "$ssh_port/tcp" comment 'SSH'

    # 询问是否开放 HTTP/HTTPS
    if confirm "是否开放 HTTP (80) 和 HTTPS (443) 端口？"; then
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'
        log_info "已开放 HTTP 和 HTTPS 端口"
    fi

    # 询问是否开放自定义端口
    if confirm "是否需要开放其他端口？"; then
        while true; do
            read -p "请输入端口号（格式: 8080/tcp 或 8080，留空结束）: " custom_port
            if [[ -z "$custom_port" ]]; then
                break
            fi

            # 如果没有指定协议，默认使用 tcp
            if [[ ! "$custom_port" =~ / ]]; then
                custom_port="$custom_port/tcp"
            fi

            read -p "请输入备注（可选）: " comment
            if [[ -n "$comment" ]]; then
                ufw allow "$custom_port" comment "$comment"
            else
                ufw allow "$custom_port"
            fi
            log_info "已添加规则: $custom_port"
        done
    fi

    # 显示规则
    log_info "当前防火墙规则："
    ufw show added

    if confirm "确认启用防火墙？" "y"; then
        # 启用防火墙
        echo "y" | ufw enable
        log_info "防火墙已启用！"

        # 显示状态
        ufw status verbose
    else
        log_warn "已取消启用防火墙"
    fi
}

#===============================================================================
# 无人值守：UFW 只放行 SSH，其他端口全部关闭
#===============================================================================
configure_ufw_unattended() {
    log_step "无人值守：配置 UFW（仅放行 SSH）"

    # 安装 UFW
    if ! command -v ufw &> /dev/null; then
        log_info "安装 UFW..."
        apt install -y ufw
    fi

    # 获取当前 SSH 端口
    local ssh_port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    log_info "检测到 SSH 端口: $ssh_port"

    log_warn "将重置 UFW 配置，仅放行 SSH 端口 $ssh_port，其他所有端口（包括 80/443）将被拒绝"

    # 硬重置 UFW 所有规则
    ufw --force reset

    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing

    # 只放行 SSH
    ufw allow "$ssh_port/tcp" comment 'SSH'

    # 启用防火墙
    ufw --force enable

    log_info "UFW 无人值守配置完成，当前状态："
    ufw status verbose
}

#===============================================================================
# 8. 修改 SSH 配置（交互）
#===============================================================================
configure_ssh() {
    log_step "配置 SSH 安全设置"

    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_backup="${ssh_config}.backup.$(date +%Y%m%d_%H%M%S)"

    log_warn "⚠️  重要提示 ⚠️"
    log_warn "修改 SSH 配置可能导致无法连接服务器！"
    log_warn "请确保："
    log_warn "  1. 已经添加了 SSH 密钥（如果要禁用密码登录）"
    log_warn "  2. 当前 SSH 连接保持打开"
    log_warn "  3. 有其他方式访问服务器（如控制台）"
    echo ""

    if ! confirm "是否继续配置 SSH？"; then
        return
    fi

    # 备份配置文件
    log_info "备份 SSH 配置到: $ssh_config_backup"
    cp "$ssh_config" "$ssh_config_backup"

    # 修改 SSH 端口
    local new_ssh_port=""
    local old_ssh_port
    old_ssh_port=$(grep "^Port " "$ssh_config" 2>/dev/null | awk '{print $2}')
    old_ssh_port=${old_ssh_port:-22}

    if confirm "是否修改 SSH 端口（默认 22）？"; then
        log_info "当前 SSH 端口: $old_ssh_port"
        read -p "请输入新的 SSH 端口号 [建议: 2222-65535]: " new_ssh_port

        if [[ -n "$new_ssh_port" ]] && [[ "$new_ssh_port" =~ ^[0-9]+$ ]]; then
            # 验证端口号范围
            if [ "$new_ssh_port" -lt 1 ] || [ "$new_ssh_port" -gt 65535 ]; then
                log_error "端口号必须在 1-65535 之间"
                return 1
            fi

            # 检查端口是否已被占用
            if ss -tuln | grep -q ":$new_ssh_port "; then
                log_warn "端口 $new_ssh_port 可能已被其他服务占用"
                if ! confirm "是否仍要继续？"; then
                    return 1
                fi
            fi

            # UFW 防火墙集成
            local ufw_enabled=false
            if command -v ufw &> /dev/null; then
                if ufw status | grep -q "Status: active"; then
                    ufw_enabled=true
                    log_info "检测到 UFW 防火墙已启用"

                    # 添加新端口
                    log_info "在 UFW 中开放新 SSH 端口 $new_ssh_port..."
                    ufw allow "$new_ssh_port/tcp" comment 'SSH'
                    log_info "✓ 已在 UFW 中开放端口 $new_ssh_port"

                    # 显示当前 SSH 相关规则
                    echo ""
                    log_info "当前 SSH 相关的防火墙规则："
                    ufw status numbered | grep -E "SSH|$old_ssh_port|$new_ssh_port" | sed 's/^/  /'

                    # 询问是否删除旧端口规则
                    if [ "$old_ssh_port" != "$new_ssh_port" ]; then
                        echo ""
                        log_warn "检测到旧 SSH 端口: $old_ssh_port"
                        if confirm "是否从 UFW 中删除旧的 SSH 端口 $old_ssh_port 规则？"; then
                            local rule_deleted=false
                            if ufw status | grep -q "$old_ssh_port/tcp"; then
                                ufw delete allow "$old_ssh_port/tcp" 2>/dev/null && rule_deleted=true
                            fi

                            if [ "$rule_deleted" = true ]; then
                                log_info "✓ 已删除旧端口 $old_ssh_port 的防火墙规则"
                            else
                                log_warn "未找到端口 $old_ssh_port 的规则，或删除失败"
                            fi
                        else
                            log_info "保留旧端口 $old_ssh_port 的防火墙规则（双端口可用）"
                        fi
                    fi

                    echo ""
                    log_info "更新后的 UFW 规则："
                    ufw status | sed 's/^/  /'
                fi
            fi

            # 修改 SSH 配置端口
            if grep -q "^Port " "$ssh_config"; then
                sed -i "s/^Port .*/Port $new_ssh_port/" "$ssh_config"
            else
                echo "Port $new_ssh_port" >> "$ssh_config"
            fi
            log_info "✓ 已在 SSH 配置中设置端口为: $new_ssh_port"

            if [ "$ufw_enabled" = false ] && command -v ufw &> /dev/null; then
                log_warn "UFW 已安装但未启用，端口修改后请记得配置防火墙"
            fi
        else
            log_error "无效的端口号"
            return 1
        fi
    fi

    # 禁用 root 登录
    if confirm "是否禁用 root 直接登录？" "y"; then
        sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' "$ssh_config"
        if ! grep -q "^PermitRootLogin" "$ssh_config"; then
            echo "PermitRootLogin no" >> "$ssh_config"
        fi
        log_info "已禁用 root 登录"
    fi

    # 禁用密码登录
    if confirm "是否禁用密码登录（仅允许密钥登录）？" "y"; then
        log_warn "请确保已经添加了 SSH 公钥，否则将无法登录！"
        if confirm "确认已添加公钥，继续禁用密码登录？"; then
            sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "$ssh_config"
            if ! grep -q "^PasswordAuthentication" "$ssh_config"; then
                echo "PasswordAuthentication no" >> "$ssh_config"
            fi

            sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/' "$ssh_config"
            if ! grep -q "^PubkeyAuthentication" "$ssh_config"; then
                echo "PubkeyAuthentication yes" >> "$ssh_config"
            fi

            log_info "已禁用密码登录，仅允许密钥登录"
        fi
    fi

    # 其他安全设置
    if confirm "是否应用其他安全设置（禁用空密码、X11转发等）？" "y"; then
        # 禁用空密码
        sed -i 's/^#*PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$ssh_config"
        if ! grep -q "^PermitEmptyPasswords" "$ssh_config"; then
            echo "PermitEmptyPasswords no" >> "$ssh_config"
        fi

        # 禁用 X11 转发
        sed -i 's/^#*X11Forwarding .*/X11Forwarding no/' "$ssh_config"
        if ! grep -q "^X11Forwarding" "$ssh_config"; then
            echo "X11Forwarding no" >> "$ssh_config"
        fi

        # 设置最大认证尝试次数
        sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' "$ssh_config"
        if ! grep -q "^MaxAuthTries" "$ssh_config"; then
            echo "MaxAuthTries 3" >> "$ssh_config"
        fi

        log_info "已应用额外安全设置"
    fi

    # 测试配置文件
    log_info "测试 SSH 配置文件语法..."
    if sshd -t; then
        log_info "✓ SSH 配置文件语法正确"
    else
        log_error "✗ SSH 配置文件语法错误！"
        log_info "恢复备份配置..."
        cp "$ssh_config_backup" "$ssh_config"
        return 1
    fi

    # 显示修改的配置
    log_info "修改后的关键配置："
    grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|MaxAuthTries)" "$ssh_config" | sed 's/^/  /'

    echo ""
    log_warn "⚠️  重要：重启 SSH 服务前请注意 ⚠️"
    if [[ -n "$new_ssh_port" ]]; then
        log_warn "  1. SSH 端口可能已从 $old_ssh_port 改为: $new_ssh_port"
        if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
            log_warn "  2. UFW 防火墙已自动配置端口 $new_ssh_port"
        fi
        log_warn "  3. 请保持当前连接，开新终端测试新端口"
        log_warn "  4. 测试命令: ssh -p $new_ssh_port user@server"
        log_warn "  5. 确认新连接成功后，再关闭当前连接"
    else
        log_warn "  1. 确认新连接成功后，再关闭当前连接"
    fi
    log_warn "  ⚠️  如果无法连接，使用控制台恢复配置："
    log_warn "     cp $ssh_config_backup $ssh_config && systemctl restart ssh"
    echo ""

    if confirm "确认重启 SSH 服务？"; then
        log_info "重启 SSH 服务..."
        systemctl restart ssh

        log_info "SSH 服务已重启"
        log_info "当前 SSH 连接仍然有效，请在新终端测试连接！"

        if [[ -n "$new_ssh_port" ]]; then
            echo ""
            log_warn "新的连接命令："
            echo "  ssh -p $new_ssh_port username@$(hostname -I | awk '{print $1}')"
        fi
    else
        log_warn "已取消重启 SSH 服务"
        log_info "配置已修改但未生效，需要手动重启: systemctl restart ssh"
    fi
}

#===============================================================================
# 无人值守：SSH 安全加固（禁用 root / 密码登录，仅密钥）
#===============================================================================
configure_ssh_hardening_unattended() {
    log_step "无人值守：SSH 安全加固"

    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_backup="${ssh_config}.backup.unattended.$(date +%Y%m%d_%H%M%S)"

    log_info "备份 SSH 配置到: $ssh_config_backup"
    cp "$ssh_config" "$ssh_config_backup"

    _set_or_append() {
        local key="$1"
        local value="$2"
        if grep -q "^$key" "$ssh_config"; then
            sed -i "s/^$key.*/$key $value/" "$ssh_config"
        else
            echo "$key $value" >> "$ssh_config"
        fi
    }

    # 禁用 root 登录
    _set_or_append "PermitRootLogin" "no"

    # 禁用密码登录，仅允许密钥
    _set_or_append "PasswordAuthentication" "no"
    _set_or_append "PubkeyAuthentication" "yes"

    # 禁用空密码
    _set_or_append "PermitEmptyPasswords" "no"

    # 禁用 X11 转发
    _set_or_append "X11Forwarding" "no"

    # 限制最大认证尝试次数
    _set_or_append "MaxAuthTries" "3"

    # 测试配置
    log_info "测试 SSH 配置语法..."
    if sshd -t; then
        log_info "✓ SSH 配置语法正确"
    else
        log_error "✗ SSH 配置语法错误，恢复备份..."
        cp "$ssh_config_backup" "$ssh_config"
        return 1
    fi

    log_info "关键配置如下："
    grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|MaxAuthTries)" "$ssh_config" | sed 's/^/  /'

    log_info "重启 SSH 服务..."
    systemctl restart ssh

    log_info "SSH 服务已重启，当前连接仍然有效，请在新终端测试登录！"
}

#===============================================================================
# 9. 安装配置 Fail2ban（交互）
#===============================================================================
install_fail2ban() {
    log_step "安装配置 Fail2ban"

    # 安装 fail2ban
    if ! command -v fail2ban-client &> /dev/null; then
        log_info "安装 fail2ban..."
        apt install -y fail2ban
    else
        log_warn "fail2ban 已安装"
    fi

    log_info "配置 fail2ban..."

    local jail_local="/etc/fail2ban/jail.local"

    # 获取 SSH 端口（自动同步 SSH 配置）
    local ssh_port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    log_info "检测到 SSH 端口: $ssh_port （自动同步）"

    cat > "$jail_local" << EOF
[DEFAULT]
# 封禁时间（秒）：10分钟
bantime = 600

# 查找时间（秒）：10分钟内
findtime = 600

# 最大重试次数
maxretry = 5

# 封禁动作（使用 iptables）
banaction = iptables-multiport

# 使用 systemd 日志
backend = systemd

[sshd]
enabled = true
port = $ssh_port
filter = sshd
maxretry = 3
bantime = 3600
findtime = 600
EOF

    log_info "Fail2ban 初始配置内容："
    sed 's/^/  /' "$jail_local"

    if confirm "是否修改封禁参数？"; then
        read -p "封禁时间（秒，默认 3600=1小时）: " bantime
        read -p "查找时间（秒，默认 600=10分钟）: " findtime
        read -p "最大重试次数（默认 3）: " maxretry

        if [[ -n "$bantime" ]]; then
            sed -i "/^\[DEFAULT\]/,/^\[/{s/^bantime = .*/bantime = $bantime/}" "$jail_local"
            sed -i "/^\[sshd\]/,/^$/s/^bantime = .*/bantime = $bantime/" "$jail_local"
        fi
        if [[ -n "$findtime" ]]; then
            sed -i "/^\[DEFAULT\]/,/^\[/{s/^findtime = .*/findtime = $findtime/}" "$jail_local"
            sed -i "/^\[sshd\]/,/^$/s/^findtime = .*/findtime = $findtime/" "$jail_local"
        fi
        if [[ -n "$maxretry" ]]; then
            sed -i "/^\[DEFAULT\]/,/^\[/{s/^maxretry = .*/maxretry = $maxretry/}" "$jail_local"
            sed -i "/^\[sshd\]/,/^$/s/^maxretry = .*/maxretry = $maxretry/" "$jail_local"
        fi
    fi

    # 询问是否添加 IP 白名单（ignoreip，多次输入）
    if confirm "是否添加 IP 白名单（这些 IP 不会被封禁）？"; then
        log_info "依次输入要加入白名单的 IP 或网段（例如 1.2.3.4 或 10.0.0.0/24）"
        log_info "直接回车结束输入"

        local ignore_list=""
        while true; do
            read -p "白名单 IP/网段（留空结束）: " ip
            if [[ -z "$ip" ]]; then
                break
            fi
            ignore_list+=" $ip"
        done

        if [[ -n "$ignore_list" ]]; then
            local ignore_line="ignoreip = 127.0.0.1/8$ignore_list"
            if grep -q "^ignoreip" "$jail_local"; then
                sed -i "s/^ignoreip.*/$ignore_line/" "$jail_local"
            else
                sed -i "/^\[DEFAULT\]/a $ignore_line" "$jail_local"
            fi
            log_info "已设置 IP 白名单:$(echo "$ignore_list")"
        else
            log_warn "未输入任何 IP，跳过白名单配置"
        fi
    fi

    log_info "最终 Fail2ban 配置："
    sed 's/^/  /' "$jail_local"

    # 启动/重启 fail2ban
    log_info "启动 fail2ban 服务..."
    systemctl enable fail2ban

    if systemctl is-active --quiet fail2ban; then
        systemctl restart fail2ban
    else
        systemctl start fail2ban
    fi

    # 简单等待服务就绪
    sleep 2

    log_info "Fail2ban 状态："
    fail2ban-client status || true

    log_info "SSH jail 状态："
    fail2ban-client status sshd 2>/dev/null || log_warn "SSH jail 可能还未完全加载"

    log_info "Fail2ban 安装配置完成！"
    echo ""
    log_info "常用命令："
    echo "  查看状态: fail2ban-client status sshd"
    echo "  解封 IP:  fail2ban-client set sshd unbanip <IP>"
    echo "  查看日志: tail -f /var/log/fail2ban.log"
}

#===============================================================================
# 无人值守：Fail2ban（固定白名单 152.53.135.0/24）
#===============================================================================
install_fail2ban_unattended() {
    log_step "无人值守：安装配置 Fail2ban"

    if ! command -v fail2ban-client &> /dev/null; then
        log_info "安装 fail2ban..."
        apt install -y fail2ban
    else
        log_info "fail2ban 已安装，覆盖配置并重新启动"
    fi

    local jail_local="/etc/fail2ban/jail.local"

    local ssh_port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    log_info "检测到 SSH 端口: $ssh_port"

    cat > "$jail_local" << EOF
[DEFAULT]
bantime  = 600
findtime = 600
maxretry = 5
banaction = iptables-multiport
backend  = systemd
ignoreip = 127.0.0.1/8 152.53.135.0/24

[sshd]
enabled  = true
port     = $ssh_port
filter   = sshd
maxretry = 3
bantime  = 3600
findtime = 600
EOF

    log_info "Fail2ban 无人值守配置写入完成："
    sed 's/^/  /' "$jail_local"

    systemctl enable fail2ban
    if systemctl is-active --quiet fail2ban; then
        systemctl restart fail2ban
    else
        systemctl start fail2ban
    fi

    # 等待 socket 就绪
    log_info "等待 Fail2ban 服务就绪..."
    local sock1="/run/fail2ban/fail2ban.sock"
    local sock2="/var/run/fail2ban/fail2ban.sock"
    local ok=false

    for i in {1..10}; do
        if [ -S "$sock1" ] || [ -S "$sock2" ]; then
            ok=true
            break
        fi
        sleep 1
    done

    if [ "$ok" = false ]; then
        log_warn "Fail2ban socket 未就绪，可能服务启动较慢或启动失败"
        log_info "当前 fail2ban 服务状态："
        systemctl status fail2ban --no-pager || true
    fi

    log_info "Fail2ban 状态："
    fail2ban-client status || true
}


#===============================================================================
# 10. 配置 SSH 登录欢迎信息（MOTD）
#===============================================================================
configure_ssh_motd() {
    log_step "配置 SSH 登录欢迎信息"

    local is_enabled=false
    if [[ -x /etc/update-motd.d/10-header ]] && [[ -x /etc/update-motd.d/20-sysinfo ]]; then
        is_enabled=true
    fi

    if [ "$is_enabled" = true ]; then
        log_info "SSH 登录欢迎信息当前状态: ${GREEN}已启用${NC}"
        echo ""
        echo "请选择操作："
        echo "  1) 禁用欢迎信息"
        echo "  2) 重新配置"
        echo "  3) 预览当前效果"
        echo "  0) 返回"
        read -p "请选择 [0-3]: " motd_action

        case $motd_action in
            1)
                log_info "禁用 SSH 登录欢迎信息..."
                chmod -x /etc/update-motd.d/10-header 2>/dev/null
                chmod -x /etc/update-motd.d/20-sysinfo 2>/dev/null
                chmod -x /etc/update-motd.d/30-users 2>/dev/null
                chmod -x /etc/update-motd.d/40-updates 2>/dev/null
                chmod -x /etc/update-motd.d/50-footer 2>/dev/null
                log_info "已禁用 SSH 登录欢迎信息"
                return
                ;;
            2)
                log_info "将重新配置 SSH 登录欢迎信息..."
                ;;
            3)
                log_info "当前欢迎信息预览："
                echo "------------------------------------------------------------"
                run-parts /etc/update-motd.d/
                echo "------------------------------------------------------------"
                return
                ;;
            0|*)
                return
                ;;
        esac
    else
        log_info "SSH 登录欢迎信息当前状态: ${YELLOW}未启用${NC}"
        echo ""
        log_info "将创建动态欢迎信息，显示："
        echo "  - 系统信息（主机名、内核版本、运行时间）"
        echo "  - CPU 负载"
        echo "  - 内存使用情况"
        echo "  - 磁盘使用情况"
        echo "  - 当前登录用户"
        echo "  - 系统更新提示"
        echo ""

        if ! confirm "是否启用 SSH 登录欢迎信息？" "y"; then
            return
        fi
    fi

    mkdir -p /etc/update-motd.d

    if [[ -f /etc/motd ]]; then
        mv /etc/motd /etc/motd.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        log_info "已备份原 /etc/motd"
    fi

    if [[ -d /etc/update-motd.d ]]; then
        chmod -x /etc/update-motd.d/* 2>/dev/null || true
    fi

    log_info "创建欢迎信息脚本..."

    # 10-header
    cat > /etc/update-motd.d/10-header << 'EOF'
#!/bin/bash
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                      欢迎登录本服务器                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

HOSTNAME=$(hostname)
KERNEL=$(uname -r)
UPTIME=$(uptime -p | sed 's/up //')
IP_ADDR=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}主机名称:${NC} $HOSTNAME"
echo -e "${GREEN}内核版本:${NC} $KERNEL"
echo -e "${GREEN}运行时间:${NC} $UPTIME"
echo -e "${GREEN}IP 地址:${NC} $IP_ADDR"
echo ""
EOF

    # 20-sysinfo
    cat > /etc/update-motd.d/20-sysinfo << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════════════"
echo "  系统资源状态"
echo "════════════════════════════════════════════════════════════════"

LOAD=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
CPU_CORES=$(nproc)
echo -e "${GREEN}CPU 核心:${NC} $CPU_CORES"
echo -e "${GREEN}系统负载:${NC} $LOAD (1min, 5min, 15min)"

MEMORY=$(free -h | awk '/^Mem:/ {print $3 "/" $2}')
MEMORY_PERCENT=$(free | awk '/^Mem:/ {printf "%d", $3/$2*100}')
if [ "$MEMORY_PERCENT" -gt 80 ]; then
   MEM_COLOR=$RED
elif [ "$MEMORY_PERCENT" -gt 60 ]; then
   MEM_COLOR=$YELLOW
else
   MEM_COLOR=$GREEN
fi
echo -e "${GREEN}内存使用:${NC} ${MEM_COLOR}$MEMORY ($MEMORY_PERCENT%)${NC}"

DISK=$(df -h / | awk 'NR==2 {print $3 "/" $2}')
DISK_PERCENT=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_PERCENT" -gt 80 ]; then
   DISK_COLOR=$RED
elif [ "$DISK_PERCENT" -gt 60 ]; then
   DISK_COLOR=$YELLOW
else
   DISK_COLOR=$GREEN
fi
echo -e "${GREEN}磁盘使用:${NC} ${DISK_COLOR}$DISK ($DISK_PERCENT%)${NC}"

echo ""
EOF

    # 30-users
    cat > /etc/update-motd.d/30-users << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════════════"
echo "  登录信息"
echo "════════════════════════════════════════════════════════════════"

USER_COUNT=$(who | wc -l)
echo -e "${GREEN}当前登录用户数:${NC} $USER_COUNT"

if [ $USER_COUNT -gt 0 ]; then
   echo ""
   who | awk '{printf "  %-12s %-12s %s %s\n", $1, $2, $3, $4}'
fi

echo ""
EOF

    # 40-updates（避免每次登陆都跑 apt list）
    cat > /etc/update-motd.d/40-updates << 'EOF'
#!/bin/bash
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════════════"

STAMP="/var/lib/apt/periodic/update-success-stamp"
if [ -f "$STAMP" ]; then
   NOW=$(date +%s)
   LAST=$(stat -c %Y "$STAMP" 2>/dev/null || echo 0)
   AGE=$((NOW - LAST))
   if [ "$AGE" -le 86400 ]; then
       UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
       if [ "$UPDATES" -gt 0 ]; then
           echo -e "${YELLOW}⚠ 有 $UPDATES 个软件包可以更新${NC}"
           echo -e "  运行 ${GREEN}sudo apt update && sudo apt upgrade${NC} 进行更新"
       else
           echo -e "${GREEN}✓ 系统软件包已是最新${NC}"
       fi
   else
       echo -e "APT 缓存较久未更新，建议运行 ${GREEN}sudo apt update${NC} 检查更新"
   fi
else
   echo -e "运行 ${GREEN}sudo apt update${NC} 检查更新"
fi

echo "════════════════════════════════════════════════════════════════"
echo ""
EOF

    # 50-footer
    cat > /etc/update-motd.d/50-footer << 'EOF'
#!/bin/bash
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}提示: 输入 'll' 查看当前目录文件列表${NC}"
echo -e "${CYAN}      输入 'htop' 查看系统进程${NC}"
echo ""
EOF

    chmod +x /etc/update-motd.d/10-header
    chmod +x /etc/update-motd.d/20-sysinfo
    chmod +x /etc/update-motd.d/30-users
    chmod +x /etc/update-motd.d/40-updates
    chmod +x /etc/update-motd.d/50-footer

    log_info "欢迎信息脚本创建完成！"

    echo ""
    log_info "预览效果："
    echo "------------------------------------------------------------"
    run-parts /etc/update-motd.d/
    echo "------------------------------------------------------------"
    echo ""

    log_info "SSH 登录欢迎信息配置完成！"
    log_info "下次 SSH 登录时将显示以上信息"
}

#===============================================================================
# 11. 用户环境配置优化（交互）
#===============================================================================
configure_user_environment() {
    log_step "用户环境配置优化"

    echo "请选择配置范围："
    echo "  1) 全局配置（所有用户）"
    echo "  2) 指定用户配置"
    read -p "请选择 [1-2]: " scope_choice

    local target_users=()
    local bashrc_files=()
    local vimrc_files=()

    case $scope_choice in
        1)
            log_info "将为所有用户配置..."
            bashrc_files=("/etc/bash.bashrc")
            vimrc_files=("/etc/vim/vimrc.local")
            ;;
        2)
            read -p "请输入用户名（多个用户用空格分隔）: " user_input
            if [[ -z "$user_input" ]]; then
                log_error "未输入用户名"
                return 1
            fi

            for username in $user_input; do
                if ! id "$username" &>/dev/null; then
                    log_error "用户 $username 不存在，跳过"
                    continue
                fi
                target_users+=("$username")
                local user_home
                user_home=$(eval echo "~$username")
                bashrc_files+=("$user_home/.bashrc")
                vimrc_files+=("$user_home/.vimrc")
            done

            if [[ ${#target_users[@]} -eq 0 ]]; then
                log_error "没有有效的用户"
                return 1
            fi

            log_info "将为以下用户配置: ${target_users[*]}"
            ;;
        *)
            log_error "无效的选择"
            return 1
            ;;
    esac

    # 检查别名配置状态
    local aliases_exist=false
    local aliases_enabled=false
    for bashrc in "${bashrc_files[@]}"; do
        if grep -q "# Custom aliases - debian12-setup" "$bashrc" 2>/dev/null; then
            aliases_exist=true
            if grep -q "^[[:space:]]*alias ll=" "$bashrc" 2>/dev/null; then
                aliases_enabled=true
            fi
            break
        fi
    done

    if [ "$aliases_exist" = true ]; then
        if [ "$aliases_enabled" = true ]; then
            log_info "实用别名当前状态: ${GREEN}已启用${NC}"
        else
            log_info "实用别名当前状态: ${YELLOW}已禁用${NC}"
        fi

        echo ""
        echo "请选择操作："
        echo "  1) $([ "$aliases_enabled" = true ] && echo "禁用别名" || echo "启用别名")"
        echo "  2) 查看当前别名"
        echo "  0) 跳过"
        read -p "请选择 [0-2]: " alias_action

        case $alias_action in
            1)
                if [ "$aliases_enabled" = true ]; then
                    log_info "禁用别名..."
                    for bashrc in "${bashrc_files[@]}"; do
                        if [[ -f "$bashrc" ]] && grep -q "# Custom aliases - debian12-setup" "$bashrc"; then
                            sed -i '/# Custom aliases - debian12-setup/,/^$/s/^[[:space:]]*alias /#alias /' "$bashrc"
                            log_info "已在 $bashrc 中禁用别名"
                        fi
                    done
                    log_info "别名已禁用，重新登录后生效"
                else
                    log_info "启用别名..."
                    for bashrc in "${bashrc_files[@]}"; do
                        if [[ -f "$bashrc" ]] && grep -q "# Custom aliases - debian12-setup" "$bashrc"; then
                            sed -i '/# Custom aliases - debian12-setup/,/^$/s/^[[:space:]]*#alias /alias /' "$bashrc"
                            log_info "已在 $bashrc 中启用别名"
                        fi
                    done
                    log_info "别名已启用，重新登录后生效"
                fi
                return
                ;;
            2)
                log_info "当前配置的别名："
                for bashrc in "${bashrc_files[@]}"; do
                    if [[ -f "$bashrc" ]]; then
                        echo ""
                        echo "文件: $bashrc"
                        echo "----------------------------------------"
                        grep "^alias\|^#alias" "$bashrc" | grep -A 50 "debian12-setup" | head -20
                    fi
                done
                return
                ;;
            0|*)
                return
                ;;
        esac
    fi

    # 首次配置别名
    if confirm "是否添加实用别名（ll, grep, df, free 等优化）？" "y"; then
        log_info "配置实用别名..."

        for bashrc in "${bashrc_files[@]}"; do
            if grep -q "# Custom aliases - debian12-setup" "$bashrc" 2>/dev/null; then
                log_warn "$bashrc 中已存在自定义别名，跳过"
                continue
            fi

            cat >> "$bashrc" << 'EOF'

# Custom aliases - debian12-setup
# LS aliases
alias ll='ls -lh --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ls='ls --color=auto'

# Grep aliases with color
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Disk and memory with human-readable sizes
alias df='df -h'
alias free='free -h'
alias du='du -h'

# Safe operations
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Directory navigation
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# Other useful aliases
alias mkdir='mkdir -pv'
alias wget='wget -c'
alias path='echo -e ${PATH//:/\\n}'
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias ports='netstat -tulanp'
EOF
            log_info "已添加到: $bashrc"
        done

        log_info "实用别名配置完成！"
        echo ""
        log_info "已添加的别名："
        echo "  ll, la, l        - ls 系列增强（ll 不显示隐藏文件）"
        echo "  grep, egrep      - 彩色搜索"
        echo "  df, free, du     - 人类可读的大小显示"
        echo "  rm, cp, mv       - 安全操作（询问确认）"
        echo "  .., ..., ....    - 快速目录跳转"
        echo "  mkdir            - 自动创建父目录"
        echo "  wget             - 断点续传"
        echo "  ports            - 查看端口占用"
    fi

    # 默认编辑器为 vim
    if confirm "是否将系统默认编辑器设置为 vim？" "y"; then
        log_info "设置默认编辑器..."

        if ! command -v vim &> /dev/null; then
            log_warn "vim 未安装，正在安装..."
            apt install -y vim
        fi

        if update-alternatives --set editor /usr/bin/vim.basic 2>/dev/null; then
            log_info "已通过 update-alternatives 设置 vim 为默认编辑器"
        elif update-alternatives --set editor /usr/bin/vim 2>/dev/null; then
            log_info "已通过 update-alternatives 设置 vim 为默认编辑器"
        else
            log_warn "update-alternatives 设置失败，将使用环境变量方式"
        fi

        for bashrc in "${bashrc_files[@]}"; do
            if ! grep -q "EDITOR=vim" "$bashrc" 2>/dev/null; then
                {
                    echo ""
                    echo "# Set default editor"
                    echo "export EDITOR=vim"
                    echo "export VISUAL=vim"
                } >> "$bashrc"
                log_info "已在 $bashrc 中设置编辑器环境变量"
            fi
        done

        log_info "默认编辑器配置完成！"
    fi

    # Vim 配置
    if confirm "是否配置 vim（语法高亮、智能缩进、粘贴模式等）？" "y"; then
        log_info "配置 vim..."

        local vim_config='
" ===================================================================
" Vim Configuration - Auto generated by debian12-setup.sh
" ===================================================================

syntax on
set nocompatible
set backspace=indent,eol,start

set encoding=utf-8
set fileencoding=utf-8
set fileencodings=utf-8,gbk,gb2312,cp936

set autoindent
set smartindent
set tabstop=4
set shiftwidth=4
set expandtab
set softtabstop=4

set hlsearch
set incsearch
set ignorecase
set smartcase

set showmatch
set matchtime=1
set cursorline
set ruler
set showcmd
set laststatus=2
set wildmenu

set pastetoggle=<F2>

set mouse=a
set selection=exclusive
set selectmode=mouse,key

if has("clipboard")
   set clipboard=unnamed
   if has("unnamedplus")
       set clipboard=unnamed,unnamedplus
   endif
endif

filetype on
filetype plugin on
filetype indent on

set lazyredraw
set ttyfast

set history=1000
set undolevels=1000
set updatetime=300
set timeoutlen=500

set noerrorbells
set novisualbell
set t_vb=

set nobackup
set noswapfile
set nowritebackup

set background=dark
if &t_Co >= 256
   colorscheme desert
endif
'

        for vimrc in "${vimrc_files[@]}"; do
            if [[ "$vimrc" == "/etc/vim/vimrc.local" ]]; then
                mkdir -p /etc/vim
            fi

            if [[ -f "$vimrc" ]]; then
                local backup="${vimrc}.backup.$(date +%Y%m%d_%H%M%S)"
                cp "$vimrc" "$backup"
                log_info "已备份原配置: $backup"
            fi

            echo "$vim_config" > "$vimrc"
            log_info "已配置: $vimrc"

            if [[ "$scope_choice" == "2" ]]; then
                for username in "${target_users[@]}"; do
                    local user_home
                    user_home=$(eval echo "~$username")
                    if [[ "$vimrc" == "$user_home/.vimrc" ]]; then
                        chown "$username:$username" "$vimrc"
                        chmod 644 "$vimrc"
                        break
                    fi
                done
            fi
        done

        log_info "Vim 配置完成！"
        echo ""
        log_info "Vim 使用提示："
        echo "  - 按 F2 切换粘贴模式（粘贴代码时使用）"
        echo "  - 支持鼠标选中和复制"
        echo "  - 自动语法高亮和智能缩进"
        echo "  - 使用 :set paste 手动开启粘贴模式"
        echo "  - 使用 :set nopaste 关闭粘贴模式"
    fi

    if [[ "$scope_choice" == "2" ]]; then
        for username in "${target_users[@]}"; do
            local user_home
            user_home=$(eval echo "~$username")
            if [[ -f "$user_home/.bashrc" ]]; then
                chown "$username:$username" "$user_home/.bashrc"
                chmod 644 "$user_home/.bashrc"
            fi
        done
    fi

    log_info "用户环境配置完成！"
    echo ""
    log_warn "提示：配置已生效，请重新登录或执行以下命令应用更改："
    if [[ "$scope_choice" == "1" ]]; then
        echo "  source /etc/bash.bashrc"
    else
        for username in "${target_users[@]}"; do
            echo "  su - $username  # 或重新登录"
        done
    fi
}

#===============================================================================
# 无人值守：用户环境配置优化（全局）
#===============================================================================
configure_user_environment_unattended() {
    log_step "无人值守：用户环境配置优化（全局）"

    local bashrc="/etc/bash.bashrc"
    local vimrc="/etc/vim/vimrc.local"

    if ! grep -q "# Custom aliases - debian12-setup" "$bashrc" 2>/dev/null; then
        cat >> "$bashrc" << 'EOF'
# Custom aliases - debian12-setup
# LS aliases
alias ll='ls -lh --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ls='ls --color=auto'

# Grep aliases with color
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Disk and memory with human-readable sizes
alias df='df -h'
alias free='free -h'
alias du='du -h'

# Safe operations
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Directory navigation
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# Other useful aliases
alias mkdir='mkdir -pv'
alias wget='wget -c'
alias path='echo -e ${PATH//:/\\n}'
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias ports='netstat -tulanp'
EOF
        log_info "已在 $bashrc 中添加全局别名"
    else
        log_info "$bashrc 中已存在 debian12-setup 别名，跳过添加"
    fi

    if ! command -v vim &> /dev/null; then
        log_info "vim 未安装，正在安装..."
        apt install -y vim
    fi

    update-alternatives --set editor /usr/bin/vim.basic 2>/dev/null || \
    update-alternatives --set editor /usr/bin/vim 2>/dev/null || \
    log_warn "update-alternatives 设置默认编辑器失败，使用环境变量兜底"

    if ! grep -q "EDITOR=vim" "$bashrc" 2>/dev/null; then
        {
            echo ""
            echo "# Set default editor (unattended)"
            echo "export EDITOR=vim"
            echo "export VISUAL=vim"
        } >> "$bashrc"
        log_info "已在 $bashrc 中设置 EDITOR/ VISUAL = vim"
    fi

    mkdir -p /etc/vim

    if [[ -f "$vimrc" ]]; then
        local backup="${vimrc}.backup.unattended.$(date +%Y%m%d_%H%M%S)"
        cp "$vimrc" "$backup"
        log_info "已备份原 vim 配置: $backup"
    fi

    cat > "$vimrc" << 'EOF'
" ===================================================================
" Vim Configuration - Auto generated by debian12-setup.sh (unattended)
" ===================================================================

syntax on
set nocompatible
set backspace=indent,eol,start

set encoding=utf-8
set fileencoding=utf-8
set fileencodings=utf-8,gbk,gb2312,cp936

set autoindent
set smartindent
set tabstop=4
set shiftwidth=4
set expandtab
set softtabstop=4

set hlsearch
set incsearch
set ignorecase
set smartcase

set showmatch
set matchtime=1
set cursorline
set ruler
set showcmd
set laststatus=2
set wildmenu

set pastetoggle=<F2>

set mouse=a
set selection=exclusive
set selectmode=mouse,key

if has("clipboard")
   set clipboard=unnamed
   if has("unnamedplus")
       set clipboard=unnamed,unnamedplus
   endif
endif

filetype on
filetype plugin on
filetype indent on

set lazyredraw
set ttyfast

set history=1000
set undolevels=1000
set updatetime=300
set timeoutlen=500

set noerrorbells
set novisualbell
set t_vb=

set nobackup
set noswapfile
set nowritebackup

set background=dark
if &t_Co >= 256
   colorscheme desert
endif
EOF

    log_info "全局 Vim 配置已写入 $vimrc"
    log_info "无人值守：用户环境配置完成（全局生效，建议重新登录以生效）"
}

#===============================================================================
# 12. 网络优化（交互）
#===============================================================================
optimize_network() {
    log_step "网络优化（BBR 等）"

    local kernel
    kernel=$(uname -r)
    log_info "当前内核版本: $kernel"

    local available
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")

    if echo "$available" | grep -qw "bbr"; then
        log_info "检测到内核支持 BBR（tcp_available_congestion_control 中包含 bbr）"
        if confirm "是否配置并启用 BBR 拥塞控制算法？" "y"; then
            local conf_bbr="/etc/sysctl.d/99-bbr.conf"
            log_info "写入 BBR 相关内核参数到 $conf_bbr"
            cat > "$conf_bbr" << 'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
            sysctl --system

            log_info "当前拥塞控制算法：$(sysctl -n net.ipv4.tcp_congestion_control)"
            log_info "当前默认队列：$(sysctl -n net.core.default_qdisc)"
        fi
    else
        log_warn "当前内核未报告支持 BBR（tcp_available_congestion_control 中没有 bbr），跳过 BBR 配置"
    fi

    if confirm "是否应用额外网络优化（提高并发连接能力，参数较保守）？" "y"; then
        local conf_net="/etc/sysctl.d/99-net-tuning.conf"
        log_info "写入网络优化参数到 $conf_net"
        cat > "$conf_net" << 'EOF'
# 提高监听队列
net.core.somaxconn=4096
net.core.netdev_max_backlog=16384

# 提高半连接队列
net.ipv4.tcp_max_syn_backlog=8192

# 减少 TIME_WAIT 持续时间
net.ipv4.tcp_fin_timeout=30

# 增大本地端口范围（适合大量出站连接）
net.ipv4.ip_local_port_range=10240 65535
EOF
        sysctl --system
        log_info "网络优化参数已应用"
    fi

    log_info "网络优化完成（已针对代理/高并发场景进行调整）"
}

#===============================================================================
# 无人值守：网络优化（自动检测是否已为 BBR）
#===============================================================================
optimize_network_unattended() {
    log_step "无人值守：网络优化（BBR 等）"

    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")

    if echo "$current_cc" | grep -qw "bbr"; then
        log_info "检测到当前已启用 BBR（net.ipv4.tcp_congestion_control = $current_cc），跳过网络优化步骤"
        return 0
    fi

    log_info "当前拥塞控制算法: $current_cc（非 BBR），尝试启用 BBR..."

    local available_cc
    available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")

    if echo "$available_cc" | grep -qw "bbr"; then
        local conf_bbr="/etc/sysctl.d/99-bbr.conf"
        cat > "$conf_bbr" << 'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
        log_info "已写入 BBR 配置到 $conf_bbr"
    else
        log_warn "内核报告可用拥塞算法为: $available_cc，其中不包含 bbr，无法启用 BBR"
    fi

    local conf_net="/etc/sysctl.d/99-net-tuning.conf"
    cat > "$conf_net" << 'EOF'
# 提高监听队列
net.core.somaxconn=4096
net.core.netdev_max_backlog=16384

# 提高半连接队列
net.ipv4.tcp_max_syn_backlog=8192

# 减少 TIME_WAIT 持续时间
net.ipv4.tcp_fin_timeout=30

# 增大本地端口范围（适合大量出站连接）
net.ipv4.ip_local_port_range=10240 65535
EOF

    log_info "已写入网络调优配置到 $conf_net"

    sysctl --system

    log_info "当前拥塞控制算法：$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未知')"
    log_info "无人值守：网络优化完成"
}

#===============================================================================
# 无人值守：创建 debian 用户（如已存在则跳过）
#===============================================================================
unattended_create_debian_user() {
    log_step "无人值守：创建 debian 用户"

    local username="debian"

    if id "$username" &>/dev/null; then
        log_warn "用户 $username 已存在，跳过创建"
        return 0
    fi

    log_info "创建用户 $username..."
    useradd -m -s /bin/bash "$username"

    log_info "锁定用户密码（仅允许密钥登录）..."
    passwd -l "$username"

    log_info "将 $username 加入 sudo 组..."
    usermod -aG sudo "$username"

    log_info "无人值守：用户 $username 创建完成"
}

#===============================================================================
# 无人值守：为 debian 用户添加固定 SSH 公钥
#===============================================================================
unattended_add_ssh_key_debian() {
    log_step "无人值守：为 debian 用户添加固定 SSH 公钥"

    local username="debian"
    local ssh_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA1kqcgRwRMYArYqNZ5Ph/fsRDYorLsgD/66GmQqjXcz"

    if ! id "$username" &>/dev/null; then
        log_error "用户 $username 不存在，无法添加 SSH 密钥"
        return 1
    fi

    local user_home
    user_home=$(eval echo "~$username")
    local ssh_dir="$user_home/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    mkdir -p "$ssh_dir"

    if grep -qF "$ssh_key" "$auth_keys" 2>/dev/null; then
        log_info "该 SSH 公钥已存在于 $auth_keys 中，跳过追加"
    else
        echo "$ssh_key" >> "$auth_keys"
        log_info "已将 SSH 公钥追加到 $auth_keys"
    fi

    chown -R "$username:$username" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_keys"

    local key_count
    key_count=$(grep -c "ssh-" "$auth_keys" 2>/dev/null || echo "0")
    log_info "当前 $auth_keys 中共有 $key_count 个公钥"

    return 0
}

#===============================================================================
# 无人值守模式：按预设步骤自动执行
#===============================================================================
run_unattended() {
    log_step "无人值守模式：按预设步骤自动初始化系统"

    log_warn "将自动执行以下步骤（中途不会再询问）："
    echo "  1) 系统更新升级"
    echo "  3) 新建用户 debian（已存在则跳过）"
    echo "  4) 为 debian 添加固定 SSH 公钥"
    echo "  5) 安装常用工具"
    echo "  7) 配置 UFW（仅放行 SSH，其他端口全部关闭）"
    echo "  8) SSH 安全设置（如 debian 用户及其公钥存在则自动加固）"
    echo "  9) 安装配置 Fail2ban（固定白名单 152.53.135.0/24）"
    echo " 11) 用户环境优化（全局别名 + vim + 编辑器）"
    echo " 12) 网络优化（若非 BBR 则启用 BBR + 调优）"
    echo ""

    sleep 2

    update_system
    unattended_create_debian_user
    unattended_add_ssh_key_debian || log_warn "为 debian 添加 SSH 公钥失败，请稍后手动检查"

    install_common_tools_unattended
    configure_ufw_unattended

    local debian_home
    if debian_home=$(eval echo "~debian" 2>/dev/null) \
       && [ -f "$debian_home/.ssh/authorized_keys" ] \
       && grep -q "ssh-" "$debian_home/.ssh/authorized_keys"; then
        configure_ssh_hardening_unattended
    else
        log_warn "未检测到 debian 用户或其 SSH 公钥，出于安全考虑【跳过】SSH 自动加固"
        log_warn "你可以在确认 debian 登录正常后，从菜单中手动执行 8) SSH 安全设置"
    fi

    install_fail2ban_unattended
    configure_user_environment_unattended
    optimize_network_unattended

    log_step "无人值守初始化完成！"
    log_info "建议开一个新的 SSH 窗口测试：debian 用户能否用密钥登录，并确认 sudo 正常可用。"
}

#===============================================================================
# 主菜单
#===============================================================================
show_menu() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     Debian 12 系统初始化配置脚本              ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  1) 系统更新升级"
    echo "  2) 安装 Docker (官方源)"
    echo "  3) 新建用户"
    echo "  4) 添加 SSH 密钥"
    echo "  5) 安装常用工具"
    echo "  6) 配置时区 (Asia/Shanghai)"
    echo "  7) 配置 UFW 防火墙"
    echo "  8) 配置 SSH 安全设置 ⚠️"
    echo "  9) 安装配置 Fail2ban"
    echo " 10) 配置 SSH 登录欢迎信息"
    echo " 11) 用户环境配置优化 (别名/vim配置/默认编辑器)"
    echo " 12) 网络优化 (BBR 等，适合代理场景)"
    echo ""
    echo "  u) 无人值守初始化（按预设步骤自动执行）"
    echo "  a) 执行全部操作（交互式）"
    echo "  0) 退出"
    echo ""
}

# 执行全部操作（交互版）
run_all() {
    log_step "开始执行全部配置"

    log_warn "将依次执行以下操作："
    echo "  1. 系统更新"
    echo "  2. 安装常用工具"
    echo "  3. 配置时区"
    echo "  4. 安装 Docker"
    echo "  5. 新建用户"
    echo "  6. 添加 SSH 密钥"
    echo "  7. 用户环境配置优化（可选）"
    echo "  8. SSH 登录欢迎信息（可选）"
    echo "  9. 配置防火墙"
    echo " 10. 安装 Fail2ban"
    echo " 11. 网络优化（可选，BBR 等）"
    echo " 12. 配置 SSH 安全设置（最后执行）"
    echo ""

    if ! confirm "确认执行全部操作？"; then
        return
    fi

    update_system
    install_common_tools
    configure_timezone
    install_docker
    create_user
    add_ssh_key

    if confirm "是否配置用户环境（实用别名、vim配置等）？"; then
        configure_user_environment
    fi

    if confirm "是否配置 SSH 登录欢迎信息（显示系统状态）？"; then
        configure_ssh_motd
    fi

    configure_ufw
    install_fail2ban

    if confirm "是否进行网络优化（启用 BBR 等，适合代理场景）？"; then
        optimize_network
    fi

    log_warn "最后一步：SSH 安全配置"
    if confirm "是否配置 SSH 安全设置（建议在其他配置完成后执行）？" "y"; then
        configure_ssh
    fi

    log_step "全部配置完成！"
    log_info "建议重启系统以应用所有更改"
    if confirm "是否现在重启系统？"; then
        reboot
    fi
}

#===============================================================================
# 主程序
#===============================================================================
main() {
    check_root

    while true; do
        show_menu
        read -p "请选择操作 [0-12/u/a]: " choice

        case $choice in
            1) update_system ;;
            2) install_docker ;;
            3) create_user ;;
            4) add_ssh_key ;;
            5) install_common_tools ;;
            6) configure_timezone ;;
            7) configure_ufw ;;
            8) configure_ssh ;;
            9) install_fail2ban ;;
            10) configure_ssh_motd ;;
            11) configure_user_environment ;;
            12) optimize_network ;;
            u|U) run_unattended ;;
            a|A) run_all ;;
            0)
                log_info "退出脚本"
                exit 0
                ;;
            *)
                log_error "无效的选择，请重新输入"
                sleep 2
                ;;
        esac

        if [[ "$choice" != "0" ]]; then
            echo ""
            read -p "按 Enter 键继续..."
        fi
    done
}

main
