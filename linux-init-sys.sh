#!/bin/bash

# Linux系统初始化脚本
# 适用于Ubuntu/Debian/CentOS/RHEL系统
# 作者: CodeHuTuTu
# 版本: 2.0

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 日志文件
LOG_FILE="/var/log/system_init.log"

# 获取操作系统信息
get_os_info() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        OS=CentOS
        VER=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release))
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    echo "检测到操作系统: $OS $VER"
}

# 检测包管理器
detect_package_manager() {
    if command -v apt-get > /dev/null; then
        PKG_MANAGER="apt-get"
        UPDATE_CMD="apt-get update"
        INSTALL_CMD="apt-get install -y"
    elif command -v yum > /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum update -y"
        INSTALL_CMD="yum install -y"
    elif command -v dnf > /dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf update -y"
        INSTALL_CMD="dnf install -y"
    else
        echo -e "${RED}错误: 未找到支持的包管理器${NC}"
        exit 1
    fi
    
    echo "使用包管理器: $PKG_MANAGER"
}

# 日志记录函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

# 打印带颜色的信息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log "[INFO] $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "[SUCCESS] $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "[WARNING] $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "[ERROR] $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 备份重要配置文件
backup_configs() {
    print_info "备份重要配置文件..."
    
    BACKUP_DIR="/root/config_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # 备份配置文件
    files_to_backup=(
        "/etc/ssh/sshd_config"
        "/etc/security/limits.conf"
        "/etc/sysctl.conf"
        "/etc/profile"
        "/etc/hosts"
        "/etc/fstab"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/"
            print_success "已备份 $file"
        fi
    done
    
    print_success "配置文件备份完成，备份目录: $BACKUP_DIR"
}

# 更新系统
update_system() {
    print_info "更新系统软件包..."
    
    case $PKG_MANAGER in
        "apt-get")
            apt-get update
            apt-get upgrade -y
            apt-get autoremove -y
            apt-get autoclean
            ;;
        "yum"|"dnf")
            $UPDATE_CMD
            $PKG_MANAGER clean all
            ;;
    esac
    
    print_success "系统更新完成"
}

# 安装基础软件包
install_basic_packages() {
    print_info "安装基础软件包..."
    
    # 基础软件包列表
    basic_packages=(
        "curl"
        "wget"
        "vim"
        "git"
        "htop"
        "tree"
        "unzip"
        "zip"
        "screen"
        "tmux"
        "rsync"
        "lsof"
        "netstat-net-tools"
        "tcpdump"
        "strace"
        "iotop"
        "iftop"
        "dstat"
    )
    
    # 根据不同系统调整包名
    case $PKG_MANAGER in
        "apt-get")
            basic_packages+=("net-tools" "build-essential" "software-properties-common")
            ;;
        "yum"|"dnf")
            basic_packages+=("net-tools" "gcc" "gcc-c++" "make" "epel-release")
            # 移除不存在的包
            basic_packages=("${basic_packages[@]/netstat-net-tools}")
            ;;
    esac
    
    for package in "${basic_packages[@]}"; do
        if [ -n "$package" ]; then
            print_info "安装 $package..."
            if $INSTALL_CMD "$package" > /dev/null 2>&1; then
                print_success "已安装 $package"
            else
                print_warning "安装 $package 失败，跳过"
            fi
        fi
    done
    
    print_success "基础软件包安装完成"
}

# 配置SSH安全
configure_ssh() {
    print_info "配置SSH安全设置..."
    
    SSH_CONFIG="/etc/ssh/sshd_config"
    
    # 备份原始配置
    cp "$SSH_CONFIG" "${SSH_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # SSH安全配置
    cat > "$SSH_CONFIG" << 'EOF'
# SSH安全配置
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# 登录配置
LoginGraceTime 60
PermitRootLogin yes
StrictModes yes
MaxAuthTries 3
MaxSessions 10

# 认证配置
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# 其他安全设置
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3

# 日志
SyslogFacility AUTH
LogLevel INFO

# SFTP配置
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    # 重启SSH服务
    systemctl restart sshd
    systemctl enable sshd
    
    print_success "SSH配置完成"
}

# 配置防火墙
configure_firewall() {
    print_info "配置防火墙..."
    
    case $PKG_MANAGER in
        "apt-get")
            # 安装并配置ufw
            $INSTALL_CMD ufw
            
            # 默认策略
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
            
            # 允许SSH
            ufw allow ssh
            
            # 允许HTTP和HTTPS
            ufw allow 80/tcp
            ufw allow 443/tcp
            
            # 启用防火墙
            ufw --force enable
            ;;
        "yum"|"dnf")
            # 配置firewalld
            systemctl start firewalld
            systemctl enable firewalld
            
            # 允许SSH
            firewall-cmd --permanent --add-service=ssh
            
            # 允许HTTP和HTTPS
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            
            # 重载配置
            firewall-cmd --reload
            ;;
    esac
    
    print_success "防火墙配置完成"
}

# 系统安全加固
security_hardening() {
    print_info "进行系统安全加固..."
    
    # 1. 设置文件权限
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 400 /etc/shadow
    chmod 400 /etc/gshadow
    
    # 2. 禁用不必要的服务
    services_to_disable=(
        "bluetooth"
        "avahi-daemon"
        "cups"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" > /dev/null 2>&1; then
            systemctl disable "$service"
            systemctl stop "$service"
            print_info "已禁用服务: $service"
        fi
    done
    
    # 3. 配置登录安全
    cat >> /etc/security/limits.conf << 'EOF'

# 登录安全限制
* soft core 0
* hard core 0
* soft nproc 65535
* hard nproc 65535
* soft nofile 65535
* hard nofile 65535
EOF
    
    # 4. 配置内核参数
    cat >> /etc/sysctl.conf << 'EOF'

# 网络安全参数
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0

# 内存保护
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# 文件系统保护
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    # 应用内核参数
    sysctl -p
    
    print_success "系统安全加固完成"
}

# 优化系统性能
optimize_performance() {
    print_info "优化系统性能..."
    
    # 1. 调整内核参数
    cat >> /etc/sysctl.conf << 'EOF'

# 性能优化参数
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_tw_buckets = 5000
EOF
    
    # 2. 优化I/O调度器
    echo 'ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/scheduler}="deadline"' > /etc/udev/rules.d/60-schedulers.rules
    
    # 3. 配置透明大页
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
    
    # 4. 添加到开机启动
    cat >> /etc/rc.local << 'EOF'

# 性能优化设置
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
EOF
    
    chmod +x /etc/rc.local
    
    print_success "系统性能优化完成"
}

# 安装Docker
install_docker() {
    print_info "安装Docker..."
    
    case $PKG_MANAGER in
        "apt-get")
            # 安装依赖
            $INSTALL_CMD apt-transport-https ca-certificates curl gnupg lsb-release
            
            # 添加Docker官方GPG密钥
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            
            # 添加Docker仓库
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            
            # 更新并安装Docker
            apt-get update
            $INSTALL_CMD docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        "yum"|"dnf")
            # 安装依赖
            $INSTALL_CMD yum-utils device-mapper-persistent-data lvm2
            
            # 添加Docker仓库
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            
            # 安装Docker
            $INSTALL_CMD docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
    esac
    
    # 启动并启用Docker
    systemctl start docker
    systemctl enable docker
    
    # 添加当前用户到docker组（如果不是root）
    if [ "$SUDO_USER" ]; then
        usermod -aG docker "$SUDO_USER"
        print_info "用户 $SUDO_USER 已添加到docker组，请重新登录以生效"
    fi
    
    print_success "Docker安装完成"
}

# 安装Docker Compose
install_docker_compose() {
    print_info "安装Docker Compose..."
    
    # 获取最新版本
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
    
    # 下载并安装
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    
    chmod +x /usr/local/bin/docker-compose
    
    # 创建软链接
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    print_success "Docker Compose安装完成，版本: $COMPOSE_VERSION"
}

# 安装Nginx
install_nginx() {
    print_info "安装Nginx..."
    
    case $PKG_MANAGER in
        "apt-get")
            $INSTALL_CMD nginx
            ;;
        "yum"|"dnf")
            $INSTALL_CMD nginx
            ;;
    esac
    
    # 启动并启用Nginx
    systemctl start nginx
    systemctl enable nginx
    
    # 创建基本配置
    cat > /etc/nginx/conf.d/default.conf << 'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src * data: 'unsafe-eval' 'unsafe-inline'" always;
    
    # 隐藏Nginx版本
    server_tokens off;
}
EOF
    
    # 测试配置并重载
    nginx -t && systemctl reload nginx
    
    print_success "Nginx安装完成"
}

# 安装MySQL/MariaDB
install_mysql() {
    print_info "安装MySQL/MariaDB..."
    
    case $PKG_MANAGER in
        "apt-get")
            $INSTALL_CMD mariadb-server mariadb-client
            ;;
        "yum"|"dnf")
            $INSTALL_CMD mariadb-server mariadb
            ;;
    esac
    
    # 启动并启用服务
    systemctl start mariadb
    systemctl enable mariadb
    
    print_info "请运行 mysql_secure_installation 来安全配置数据库"
    print_success "MySQL/MariaDB安装完成"
}

# 安装PHP
install_php() {
    print_info "安装PHP..."
    
    case $PKG_MANAGER in
        "apt-get")
            $INSTALL_CMD php-fpm php-mysql php-curl php-gd php-intl php-mbstring php-soap php-xml php-xmlrpc php-zip
            ;;
        "yum"|"dnf")
            $INSTALL_CMD php php-fpm php-mysqlnd php-curl php-gd php-intl php-mbstring php-soap php-xml php-xmlrpc php-zip
            ;;
    esac
    
    # 启动并启用PHP-FPM
    systemctl start php-fpm
    systemctl enable php-fpm
    
    print_success "PHP安装完成"
}

# 安装Node.js
install_nodejs() {
    print_info "安装Node.js..."
    
    # 安装NodeSource仓库
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    
    case $PKG_MANAGER in
        "apt-get")
            $INSTALL_CMD nodejs
            ;;
        "yum"|"dnf")
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash -
            $INSTALL_CMD nodejs npm
            ;;
    esac
    
    # 安装常用全局包
    npm install -g pm2 yarn
    
    print_success "Node.js安装完成"
}

# 安装Python开发环境
install_python() {
    print_info "安装Python开发环境..."
    
    case $PKG_MANAGER in
        "apt-get")
            $INSTALL_CMD python3 python3-pip python3-dev python3-venv
            ;;
        "yum"|"dnf")
            $INSTALL_CMD python3 python3-pip python3-devel
            ;;
    esac
    
    # 升级pip
    python3 -m pip install --upgrade pip
    
    # 安装常用包
    pip3 install virtualenv virtualenvwrapper
    
    print_success "Python开发环境安装完成"
}

# 安装监控工具
install_monitoring_tools() {
    print_info "安装监控工具..."
    
    # 安装Netdata
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait
    
    # 安装Prometheus Node Exporter
    useradd --no-create-home --shell /bin/false node_exporter
    
    wget https://github.com/prometheus/node_exporter/releases/latest/download/node_exporter-1.3.1.linux-amd64.tar.gz
    tar xvf node_exporter-1.3.1.linux-amd64.tar.gz
    cp node_exporter-1.3.1.linux-amd64/node_exporter /usr/local/bin/
    chown node_exporter:node_exporter /usr/local/bin/node_exporter
    
    # 创建systemd服务
    cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl start node_exporter
    systemctl enable node_exporter
    
    rm -rf node_exporter-1.3.1.linux-amd64*
    
    print_success "监控工具安装完成"
}

# 安装fail2ban
install_fail2ban() {
    print_info "安装fail2ban..."
    
    case $PKG_MANAGER in
        "apt-get")
            $INSTALL_CMD fail2ban
            ;;
        "yum"|"dnf")
            $INSTALL_CMD fail2ban
            ;;
    esac
    
    # 询问用户是否要添加白名单IP
    echo
    read -p "是否要添加白名单IP到fail2ban的ignoreip配置? (y/n): " -n 1 -r
    echo
    
    WHITELIST_IPS=""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "请输入要添加到白名单的IP地址或CIDR范围 (每行一个，输入空行结束):"
        echo "示例: 192.168.1.100, 10.0.0.0/8, 172.16.0.0/12"
        
        while true; do
            read -p "IP/CIDR: " ip_input
            
            # 如果输入为空，结束输入
            if [ -z "$ip_input" ]; then
                break
            fi
            
            # 验证IP格式
            if validate_ip_format "$ip_input"; then
                if [ -z "$WHITELIST_IPS" ]; then
                    WHITELIST_IPS="$ip_input"
                else
                    WHITELIST_IPS="$WHITELIST_IPS $ip_input"
                fi
                print_success "已添加: $ip_input"
            else
                print_warning "无效的IP格式: $ip_input，请重新输入"
            fi
        done
    fi
    
    # 询问参数配置
    echo
    read -p "是否要配置fail2ban参数? (y/n): " -n 1 -r
    echo
    
    BANTIME="10m"
    FINDTIME="10m"
    MAXRETRY="5"
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "封禁时间 (默认10m): " input_bantime
        read -p "查找时间窗口 (默认10m): " input_findtime
        read -p "最大重试次数 (默认5): " input_maxretry
        
        [ -n "$input_bantime" ] && BANTIME="$input_bantime"
        [ -n "$input_findtime" ] && FINDTIME="$input_findtime"
        [ -n "$input_maxretry" ] && MAXRETRY="$input_maxretry"
    fi
    
    # 构建ignoreip行
    IGNOREIP_LINE="ignoreip = 127.0.0.1/8 ::1"
    if [ -n "$WHITELIST_IPS" ]; then
        IGNOREIP_LINE="$IGNOREIP_LINE $WHITELIST_IPS"
    fi
    
    # 创建jail.local配置
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
${IGNOREIP_LINE}
bantime = ${BANTIME}
findtime = ${FINDTIME}
maxretry = ${MAXRETRY}

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
EOF
    
    # 启动并启用fail2ban
    systemctl start fail2ban
    systemctl enable fail2ban
    
    print_success "fail2ban安装完成"
    if [ -n "$WHITELIST_IPS" ]; then
        print_info "已添加白名单IP: $WHITELIST_IPS"
    fi
}

# 验证IP格式的函数
validate_ip_format() {
    local ip="$1"
    
    # 检查是否包含CIDR符号
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        # CIDR格式验证
        local ip_part="${ip%/*}"
        local cidr_part="${ip#*/}"
        
        # 验证IP部分
        if validate_single_ip "$ip_part"; then
            # 验证CIDR部分 (0-32)
            if [ "$cidr_part" -ge 0 ] && [ "$cidr_part" -le 32 ]; then
                return 0
            fi
        fi
    elif [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # 单个IP格式验证
        validate_single_ip "$ip"
        return $?
    fi
    
    return 1
}

# 验证单个IP地址的函数
validate_single_ip() {
    local ip="$1"
    local IFS='.'
    local -a octets=($ip)
    
    # 检查是否有4个部分
    if [ ${#octets[@]} -ne 4 ]; then
        return 1
    fi
    
    # 检查每个部分是否在0-255范围内
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    
    return 0
}

# 配置自动备份
setup_backup() {
    print_info "设置自动备份..."
    
    # 创建备份脚本
    cat > /usr/local/bin/system_backup.sh << 'EOF'
#!/bin/bash

# 系统备份脚本
BACKUP_DIR="/backup/$(date +%Y%m%d)"
LOG_FILE="/var/log/backup.log"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 记录日志
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

log "开始系统备份"

# 备份系统配置
tar -czf "$BACKUP_DIR/etc_config.tar.gz" /etc/ 2>/dev/null
log "配置文件备份完成"

# 备份用户数据
tar -czf "$BACKUP_DIR/home_data.tar.gz" /home/ 2>/dev/null
log "用户数据备份完成"

# 备份数据库（如果存在）
if command -v mysqldump > /dev/null; then
    mysqldump --all-databases > "$BACKUP_DIR/mysql_all.sql"
    log "MySQL数据库备份完成"
fi

# 清理7天前的备份
find /backup -type d -mtime +7 -exec rm -rf {} \;
log "清理旧备份完成"

log "系统备份完成"
EOF
    
    chmod +x /usr/local/bin/system_backup.sh
    
    # 添加到crontab（每天凌晨2点执行）
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/system_backup.sh") | crontab -
    
    print_success "自动备份设置完成，每天凌晨2点执行"
}

# 配置日志轮转
setup_logrotate() {
    print_info "配置日志轮转..."
    
    cat > /etc/logrotate.d/system_init << 'EOF'
/var/log/system_init.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}

/var/log/backup.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
    
    print_success "日志轮转配置完成"
}

# 创建系统监控脚本
create_monitoring_script() {
    print_info "创建系统监控脚本..."
    
    cat > /usr/local/bin/system_monitor.sh << 'EOF'
#!/bin/bash

# 系统监控脚本
THRESHOLD_CPU=80
THRESHOLD_MEM=80
THRESHOLD_DISK=85
LOG_FILE="/var/log/system_monitor.log"
ALERT_EMAIL="admin@example.com"

# 记录日志
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

# 发送告警
send_alert() {
    local subject="$1"
    local message="$2"
    
    # 如果系统支持邮件发送
    if command -v mail > /dev/null; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
    fi
    
    log "ALERT: $subject - $message"
}

# 检查CPU使用率
check_cpu() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
    cpu_usage=${cpu_usage%.*}
    
    if [ "$cpu_usage" -gt "$THRESHOLD_CPU" ]; then
        send_alert "CPU使用率过高" "CPU使用率: ${cpu_usage}%"
    fi
}

# 检查内存使用率
check_memory() {
    local mem_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
    
    if [ "$mem_usage" -gt "$THRESHOLD_MEM" ]; then
        send_alert "内存使用率过高" "内存使用率: ${mem_usage}%"
    fi
}

# 检查磁盘使用率
check_disk() {
    df -h | awk 'NR>1 {print $5 " " $6}' | while read line; do
        usage=$(echo "$line" | awk '{print $1}' | sed 's/%//')
        partition=$(echo "$line" | awk '{print $2}')
        
        if [ "$usage" -gt "$THRESHOLD_DISK" ]; then
            send_alert "磁盘使用率过高" "分区 $partition 使用率: ${usage}%"
        fi
    done
}

# 检查系统负载
check_load() {
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | sed 's/^ *//')
    local cpu_cores=$(nproc)
    
    if (( $(echo "$load_avg > $cpu_cores" | bc -l) )); then
        send_alert "系统负载过高" "当前负载: $load_avg, CPU核数: $cpu_cores"
    fi
}

# 执行监控检查
log "开始系统监控检查"
check_cpu
check_memory
check_disk
check_load
log "系统监控检查完成"
EOF
    
    chmod +x /usr/local/bin/system_monitor.sh
    
    # 添加到crontab（每5分钟执行一次）
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/system_monitor.sh") | crontab -
    
    print_success "系统监控脚本创建完成"
}

# 配置用户环境
configure_user_environment() {
    print_info "配置用户环境..."
    
    # 配置bash别名和函数
    cat >> /etc/bash.bashrc << 'EOF'

# 系统管理别名
alias ll='ls -lh --color=auto'
alias la='ls -lah --color=auto'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# 系统信息
alias sysinfo='echo "=== 系统信息 ===" && uname -a && echo && echo "=== 内存使用 ===" && free -h && echo && echo "=== 磁盘使用 ===" && df -h && echo && echo "=== 系统负载 ===" && uptime'

# 网络相关
alias myip='curl -s ipinfo.io/ip'
alias ports='netstat -tulanp'

# 进程管理
alias pscpu='ps auxf | sort -nr -k 3'
alias psmem='ps auxf | sort -nr -k 4'

# 快速编辑
alias bashrc='vim ~/.bashrc'
alias vimrc='vim ~/.vimrc'

# 安全相关
alias rootlogin='grep "root" /var/log/auth.log | grep "session opened"'
alias failedlogin='grep "Failed password" /var/log/auth.log'
EOF
    
    # 配置vim
    cat > /etc/vim/vimrc.local << 'EOF'
" 基础设置
set number
set relativenumber
set cursorline
set hlsearch
set incsearch
set ignorecase
set smartcase
set autoindent
set smartindent
set expandtab
set tabstop=4
set shiftwidth=4
set softtabstop=4
set wrap
set linebreak
set mouse=a
set clipboard=unnamedplus

" 颜色设置
syntax enable
set background=dark
colorscheme desert

" 状态栏
set laststatus=2
set statusline=%F%m%r%h%w\ [FORMAT=%{&ff}]\ [TYPE=%Y]\ [POS=%l,%v][%p%%]\ %{strftime(\"%d/%m/%y\ -\ %H:%M\")}

" 文件编码
set encoding=utf-8
set fileencodings=ucs-bom,utf-8,cp936,gb18030,big5,euc-jp,euc-kr,latin1

" 快捷键
map <F2> :NERDTreeToggle<CR>
map <F3> :set nu!<CR>
map <F4> :set wrap!<CR>
EOF
    
    print_success "用户环境配置完成"
}

# 创建系统信息脚本
create_sysinfo_script() {
    print_info "创建系统信息脚本..."
    
    cat > /usr/local/bin/sysinfo << 'EOF'
#!/bin/bash

# 系统信息显示脚本

echo -e "\033[1;32m=== 系统基本信息 ===\033[0m"
echo "主机名: $(hostname)"
echo "操作系统: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "内核版本: $(uname -r)"
echo "系统架构: $(uname -m)"
echo "运行时间: $(uptime -p)"
echo

echo -e "\033[1;32m=== CPU信息 ===\033[0m"
echo "CPU型号: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//')"
echo "CPU核数: $(nproc)"
echo "CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')%"
echo

echo -e "\033[1;32m=== 内存信息 ===\033[0m"
free -h
echo

echo -e "\033[1;32m=== 磁盘使用 ===\033[0m"
df -h | grep -E '^/dev/'
echo

echo -e "\033[1;32m=== 网络接口 ===\033[0m"
ip addr show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://'
echo

echo -e "\033[1;32m=== 系统负载 ===\033[0m"
uptime
echo

echo -e "\033[1;32m=== 最近登录 ===\033[0m"
last -5
echo

echo -e "\033[1;32m=== 进程TOP5 ===\033[0m"
ps aux --sort=-%cpu | head -6
EOF
    
    chmod +x /usr/local/bin/sysinfo
    
    print_success "系统信息脚本创建完成，使用 'sysinfo' 命令查看"
}

# 清理系统
cleanup_system() {
    print_info "清理系统..."
    
    case $PKG_MANAGER in
        "apt-get")
            apt-get autoremove -y
            apt-get autoclean
            ;;
        "yum"|"dnf")
            $PKG_MANAGER autoremove -y
            $PKG_MANAGER clean all
            ;;
    esac
    
    # 清理临时文件
    find /tmp -type f -atime +7 -delete 2>/dev/null || true
    find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
    
    # 清理日志文件
    find /var/log -name "*.log" -type f -size +100M -exec truncate -s 0 {} \;
    
    print_success "系统清理完成"
}

# 生成系统报告
generate_report() {
    print_info "生成系统初始化报告..."
    
    REPORT_FILE="/root/system_init_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$REPORT_FILE" << EOF
=====================================
    Linux系统初始化报告
=====================================

初始化时间: $(date)
操作系统: $OS $VER
包管理器: $PKG_MANAGER

=== 已安装的软件 ===
EOF
    
    # 检查已安装的软件
    software_list=(
        "curl"
        "wget"
        "vim"
        "git"
        "htop"
        "docker"
        "nginx"
        "mysql"
        "php"
        "nodejs"
        "python3"
        "fail2ban"
    )
    
    for software in "${software_list[@]}"; do
        if command -v "$software" > /dev/null 2>&1; then
            version=$(command -v "$software" && $software --version 2>/dev/null | head -1)
            echo "✓ $software: $version" >> "$REPORT_FILE"
        else
            echo "✗ $software: 未安装" >> "$REPORT_FILE"
        fi
    done
    
    cat >> "$REPORT_FILE" << EOF

=== 服务状态 ===
EOF
    
    # 检查服务状态
    services=(
        "ssh"
        "nginx"
        "mysql"
        "docker"
        "fail2ban"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active "$service" > /dev/null 2>&1; then
            echo "✓ $service: 运行中" >> "$REPORT_FILE"
        else
            echo "✗ $service: 未运行" >> "$REPORT_FILE"
        fi
    done
    
    cat >> "$REPORT_FILE" << EOF

=== 安全配置 ===
✓ SSH配置优化
✓ 防火墙配置
✓ 系统安全加固
✓ fail2ban入侵防护

=== 性能优化 ===
✓ 内核参数优化
✓ I/O调度器优化
✓ 透明大页禁用

=== 监控和备份 ===
✓ 系统监控脚本
✓ 自动备份配置
✓ 日志轮转配置

=== 重要文件位置 ===
- 配置备份: $BACKUP_DIR
- 初始化日志: $LOG_FILE
- 系统监控日志: /var/log/system_monitor.log
- 备份日志: /var/log/backup.log

=== 常用命令 ===
- sysinfo: 查看系统信息
- /usr/local/bin/system_monitor.sh: 手动运行系统监控
- /usr/local/bin/system_backup.sh: 手动运行系统备份

=== 注意事项 ===
1. 请及时更改默认密码
2. 配置SSH密钥认证
3. 根据需要调整防火墙规则
4. 定期检查系统日志
5. 保持系统更新

报告生成完成: $(date)
EOF
    
    print_success "系统报告已生成: $REPORT_FILE"
}

# 主菜单
show_menu() {
    clear
    echo -e "${CYAN}"
    echo "=========================================="
    echo "         Linux系统初始化脚本 v2.0"
    echo "=========================================="
    echo -e "${NC}"
    echo -e "${WHITE}选择要执行的操作:${NC}"
    echo
    echo -e "${GREEN}基础设置:${NC}"
    echo "  1) 完整初始化 (推荐)"
    echo "  2) 系统更新"
    echo "  3) 安装基础软件包"
    echo "  4) SSH安全配置"
    echo "  5) 防火墙配置"
    echo "  6) 系统安全加固"
    echo "  7) 性能优化"
    echo
    echo -e "${GREEN}服务安装:${NC}"
    echo " 10) 安装Docker"
    echo " 11) 安装Docker Compose"
    echo " 12) 安装Nginx"
    echo " 13) 安装MySQL/MariaDB"
    echo " 14) 安装PHP"
    echo " 15) 安装Node.js"
    echo " 16) 安装Python环境"
    echo " 17) 安装监控工具"
    echo " 18) 安装fail2ban"
    echo
    echo -e "${GREEN}系统管理:${NC}"
    echo " 20) 配置自动备份"
    echo " 21) 配置日志轮转"
    echo " 22) 创建监控脚本"
    echo " 23) 配置用户环境"
    echo " 24) 创建系统信息脚本"
    echo " 25) 系统清理"
    echo
    echo -e "${GREEN}其他:${NC}"
    echo " 30) 生成系统报告"
    echo " 31) 查看系统信息"
    echo "  0) 退出"
    echo
    echo -e "${YELLOW}=========================================${NC}"
}

# 完整初始化
full_initialization() {
    print_info "开始完整系统初始化..."
    
    backup_configs
    update_system
    install_basic_packages
    configure_ssh
    configure_firewall
    security_hardening
    optimize_performance
    install_fail2ban
    setup_backup
    setup_logrotate
    create_monitoring_script
    configure_user_environment
    create_sysinfo_script
    cleanup_system
    generate_report
    
    print_success "完整系统初始化完成!"
}

# 主程序
main() {
    # 检查root权限
    check_root
    
    # 初始化日志
    touch "$LOG_FILE"
    log "系统初始化脚本启动"
    
    # 获取系统信息
    get_os_info
    detect_package_manager
    
    # 显示菜单和处理用户选择
    while true; do
        show_menu
        read -p "请输入选项 [0-31]: " choice
        
        case $choice in
            1)
                full_initialization
                ;;
            2)
                update_system
                ;;
            3)
                install_basic_packages
                ;;
            4)
                configure_ssh
                ;;
            5)
                configure_firewall
                ;;
            6)
                security_hardening
                ;;
            7)
                optimize_performance
                ;;
            10)
                install_docker
                ;;
            11)
                install_docker_compose
                ;;
            12)
                install_nginx
                ;;
            13)
                install_mysql
                ;;
            14)
                install_php
                ;;
            15)
                install_nodejs
                ;;
            16)
                install_python
                ;;
            17)
                install_monitoring_tools
                ;;
            18)
                install_fail2ban
                ;;
            20)
                setup_backup
                ;;
            21)
                setup_logrotate
                ;;
            22)
                create_monitoring_script
                ;;
            23)
                configure_user_environment
                ;;
            24)
                create_sysinfo_script
                ;;
            25)
                cleanup_system
                ;;
            30)
                generate_report
                ;;
            31)
                if command -v sysinfo > /dev/null; then
                    sysinfo
                else
                    print_warning "系统信息脚本未安装，请先选择选项24"
                fi
                ;;
            0)
                print_info "退出系统初始化脚本"
                log "系统初始化脚本结束"
                exit 0
                ;;
            *)
                print_error "无效选项，请重新选择"
                ;;
        esac
        
        echo
        read -p "按Enter键继续..." -r
    done
}

# 捕获中断信号
trap 'print_error "脚本被中断"; exit 1' INT TERM

# 执行主程序
main "$@"