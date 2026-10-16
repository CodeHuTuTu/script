#!/bin/bash
# Debian/Ubuntu 系统初始化。必须使用 Bash；source 默认只加载函数，不执行安装。
# 运行菜单，退出后自动刷新当前终端的别名/EDITOR：source ./init-new-system.sh --run
# 仅刷新当前终端：source ./init-new-system.sh --refresh-env

# 子进程无法修改父 Bash，必须由父 Bash source 本段才能更新当前终端；禁用别名时先清除旧定义。
if [[ "${BASH_SOURCE[0]}" != "$0" && ( "${1:-}" == --run || "${1:-}" == --refresh-env ) ]]; then
    if [[ "$1" == --run ]]; then
        # 菜单在独立的 bash 子进程中运行（不污染当前 Shell）；仅当 Bash 配置实际变化时才重新加载。
        __ps_before=$(cksum /etc/bash.bashrc "$HOME/.bashrc" 2>/dev/null)
        if (( EUID == 0 )); then bash "${BASH_SOURCE[0]}" --auto-refresh; else sudo bash "${BASH_SOURCE[0]}" --auto-refresh; fi
        __ps_rc=$?
        if [[ "$(cksum /etc/bash.bashrc "$HOME/.bashrc" 2>/dev/null)" == "$__ps_before" ]]; then
            unset __ps_before; set -- "$__ps_rc"; unset __ps_rc; return "$1"
        fi
        unset __ps_before
    fi
    unalias ll la l ls grep egrep fgrep df free du rm cp mv .. ... .... mkdir wget path now ports 2>/dev/null || true
    # shellcheck disable=SC1091
    if [[ -r /etc/bash.bashrc ]]; then source /etc/bash.bashrc || return 1; fi
    # shellcheck disable=SC1091
    if [[ -r "$HOME/.bashrc" ]]; then source "$HOME/.bashrc" || return 1; fi
    printf '%s\n' '当前 Bash 的别名和环境变量已重新加载。'
    set -- "${__ps_rc:-0}"; unset __ps_rc; return "$1"
fi

SYSTEMD_UNIT_ROOT=/etc/systemd/system
SSH_CONFIG=/etc/ssh/sshd_config
SSH_MANAGED=/etc/ssh/properties-script.conf
FAIL2BAN_CONFIG=/etc/fail2ban/jail.d/99-properties-script.local
GLOBAL_BASHRC=/etc/bash.bashrc
GLOBAL_VIMRC=/etc/vim/vimrc.local
MOTD_FILE=/etc/update-motd.d/60-properties-script
BACKUP_ROOT=/var/backups/properties-script-init
BACKUP_DIR=
SSH_SERVICE=
SSH_SOCKET=
SSH_SOCKET_FILE=
SSH_SOCKET_LISTENERS=
# Ubuntu 23.04+：sshd-socket-generator 在 daemon-reload 时按 sshd_config 的 Port/ListenAddress 生成 socket 监听，
# 其 addresses.conf 排序在本脚本 drop-in 之后并会重置 ListenStream；有它时只改 sshd_config。Debian 没有此生成器。
SSH_SOCKET_GENERATOR=/usr/lib/systemd/system-generators/sshd-socket-generator
ALIASES_BEGIN='# BEGIN properties-script aliases'
ALIASES_END='# END properties-script aliases'
EDITOR_BEGIN='# BEGIN properties-script editor'
EDITOR_END='# END properties-script editor'
VIM_BEGIN='" BEGIN properties-script vim'
VIM_END='" END properties-script vim'
SSH_BEGIN='# BEGIN properties-script ssh include'
SSH_END='# END properties-script ssh include'
UFW_AFTER_RULES=/etc/ufw/after.rules
UFW_DOCKER_BEGIN='# BEGIN properties-script ufw-docker'
UFW_DOCKER_END='# END properties-script ufw-docker'
FSTAB=/etc/fstab
SWAP_FILE=/swapfile
SWAP_SYSCTL=/etc/sysctl.d/90-properties-script-swap.conf
SWAP_BEGIN='# BEGIN properties-script swap'
SWAP_END='# END properties-script swap'
# swap 文件最小值，以及创建后根分区至少保留的可用空间（MiB）。
SWAP_MIN_MIB=128
SWAP_RESERVE_MIB=1024
# 本次运行改过别名/EDITOR 时记录范围，退出菜单时再次提示刷新父终端。
ENV_REFRESH_SCOPE=
# 由 source --run 启动时为 yes：父 Bash 会在退出后自动刷新，无需提示手动命令。
AUTO_REFRESH=no
MANAGED_ALIAS_NAMES='ll la l ls grep egrep fgrep df free du rm cp mv .. ... .... mkdir wget path now ports'
# 与 optimize-vps.sh 共用同一把锁；放在仅 root 可写的 /run，避免 /run/lock 中的符号链接攻击。
LOCK_FILE=/run/properties-script.lock

# 仅在终端中着色；NO_COLOR 或重定向到文件时输出纯文本。
if [[ -t 1 && -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_CYAN=$'\e[36m'
else
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN=''
fi
log_info() { printf '%s[INFO]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
log_warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_error() { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
log_step() { printf '\n%s==== %s ====%s\n' "$C_BOLD$C_CYAN" "$*" "$C_RESET"; }
ask() { IFS= read -r -p "$1" "$2" || { log_warn '输入结束，取消当前操作'; return 1; }; }
confirm() {
    local response prompt="$1" default="${2:-n}"
    [[ "$default" == y ]] && prompt+=' [Y/n]: ' || prompt+=' [y/N]: '
    ask "$prompt" response || return 1
    response="${response:-$default}"
    [[ "${response,,}" == y || "${response,,}" == yes ]]
}
acquire_lock() {
    command -v flock >/dev/null 2>&1 || { log_warn '缺少 flock，无法阻止多个实例并发修改'; return 0; }
    exec 9> "$LOCK_FILE" || return 1
    flock -n 9 || { log_error '另一个 properties-script 脚本正在运行，请等待其结束'; return 1; }
}
# sudo 默认 env_reset 会清除 SSH_CONNECTION；从祖先进程环境中找回，用于保留当前入口端口及 Match 地址校验。
detect_ssh_connection() {
    local pid=$$ depth value
    [[ -z "${SSH_CONNECTION:-}" ]] || return 0
    for depth in 1 2 3 4 5 6 7 8; do
        pid=$(awk '$1 == "PPid:" {print $2}' "/proc/$pid/status" 2>/dev/null)
        if ! [[ "$pid" =~ ^[0-9]+$ ]] || (( pid <= 1 )); then break; fi
        value=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | awk '/^SSH_CONNECTION=/ {sub(/^SSH_CONNECTION=/, ""); print; exit}')
        if [[ "$value" =~ ^[0-9A-Fa-f.:%]+\ [0-9]+\ [0-9A-Fa-f.:%]+\ [0-9]+$ ]]; then
            SSH_CONNECTION="$value"
            log_info "已从父进程恢复 SSH 连接信息（第 ${depth} 层）"
            return 0
        fi
    done
    [[ -z "${SUDO_USER:-}" ]] || log_warn '未能获取当前 SSH 连接信息；端口保护仅依据 sshd 配置与监听状态，Match Address 以 127.0.0.1 校验'
}
apt_get() {
    # 新装云主机常有 cloud-init/unattended-upgrades 占用 dpkg 锁；等待而非立即失败。旧版 apt 会忽略未知配置项。
    # needrestart（Ubuntu Server 默认安装）会在 apt 结束时弹窗或自动重启服务（含 sshd/docker/fail2ban）；
    # 本脚本执行中只列出需重启的服务（l），由管理员在维护窗口处理。
    if command -v needrestart >/dev/null 2>&1; then
        NEEDRESTART_MODE=l apt-get -o DPkg::Lock::Timeout=300 "$@"
    else
        apt-get -o DPkg::Lock::Timeout=300 "$@"
    fi
}
require_commands() {
    local command_name
    for command_name in "$@"; do
        command -v "$command_name" >/dev/null 2>&1 || { log_error "缺少命令: $command_name"; return 1; }
    done
}
# ---- 发行版检测（与 optimize-vps.sh 保持一致）----
# 已验证的版本。其他 Debian/Ubuntu 版本需交互确认后才继续；其他发行版（含衍生版）一律拒绝。
SUPPORTED_DEBIAN='12 13'
SUPPORTED_UBUNTU='22.04 24.04 26.04'
OS_ID=
OS_VERSION=
OS_CODENAME=
OS_NAME=
check_root() {
    [[ $EUID -eq 0 ]] || { log_error "必须以 root 运行，请执行: sudo bash $0"; return 1; }
}
# 只解析需要的字段，不 source：避免执行文件内容，也不污染全局变量。
read_os_release() {
    local key value file=/etc/os-release
    [[ -r "$file" ]] || file=/usr/lib/os-release
    [[ -r "$file" ]] || { log_error '无法读取 /etc/os-release，无法识别发行版'; return 1; }
    OS_ID=; OS_VERSION=; OS_CODENAME=; OS_NAME=
    while IFS='=' read -r key value; do
        value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
        case "$key" in
            ID) OS_ID="$value" ;;
            VERSION_ID) OS_VERSION="$value" ;;
            VERSION_CODENAME) OS_CODENAME="$value" ;;
            PRETTY_NAME) OS_NAME="$value" ;;
        esac
    done < "$file"
}
check_os() {
    local supported version matched=no
    [[ "$(uname -s)" == Linux && ${BASH_VERSINFO[0]} -ge 4 ]] || { log_error '需要 Linux 和 Bash 4+'; return 1; }
    read_os_release || return 1
    case "$OS_ID" in
        debian) supported="$SUPPORTED_DEBIAN" ;;
        ubuntu) supported="$SUPPORTED_UBUNTU" ;;
        *) log_error "仅支持 Debian/Ubuntu，当前为 ${OS_NAME:-${OS_ID:-未知}}（不自动兼容衍生发行版）"; return 1 ;;
    esac
    [[ "$OS_CODENAME" =~ ^[a-z]+$ ]] || { log_error "无法识别发行版代号: ${OS_CODENAME:-空}"; return 1; }
    for version in $supported; do [[ "$OS_VERSION" != "$version" ]] || matched=yes; done
    log_info "系统: ${OS_NAME:-$OS_ID} [${OS_ID} ${OS_VERSION:-无版本号} ${OS_CODENAME}]"
    if [[ "$matched" != yes ]]; then
        log_warn "此版本未经验证。已验证: Debian ${SUPPORTED_DEBIAN// //}，Ubuntu ${SUPPORTED_UBUNTU// //}"
        if ! [[ -t 0 ]] || ! confirm '未验证版本可能遇到软件包或命令不兼容，仍要继续？'; then log_error '已按版本检查停止'; return 1; fi
        log_warn '按未验证版本继续，请先在测试机验证'
    fi
}
check_system() {
    check_root && check_os || return 1
    [[ -d /run/systemd/system ]] || { log_error '需要运行中的 systemd；不支持直接在普通容器中初始化'; return 1; }
    require_commands apt-get dpkg systemctl getent id awk sed mktemp install cp mv stat runuser
}
valid_uint() { [[ "$1" =~ ^[0-9]{1,10}$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }
valid_port() { valid_uint "$1" 1 65535; }
user_home() { getent passwd "$1" | awk -F: 'NR == 1 {print $6}'; }
validate_user() {
    if ! [[ "$1" =~ ^[a-z_][a-z0-9_.-]*\$?$ ]] || ! id -- "$1" >/dev/null 2>&1; then log_error "无效或不存在的用户名: $1"; return 1; fi
}
start_change() {
    [[ ! -L "$BACKUP_ROOT" && ( ! -e "$BACKUP_ROOT" || ( -d "$BACKUP_ROOT" && -O "$BACKUP_ROOT" ) ) ]] || { log_error '备份根目录不是当前用户所有的普通目录'; return 1; }
    install -d -m 0700 "$BACKUP_ROOT" || return 1
    BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/change-$(date +%Y%m%d_%H%M%S)-XXXXXX") || return 1
    : > "$BACKUP_DIR/files.list" || return 1
}
backup_file() {
    local file="$1" saved="$BACKUP_DIR/files/${1#/}"
    [[ -n "$BACKUP_DIR" && ! -L "$file" ]] || { log_error "拒绝操作符号链接: $file"; return 1; }
    [[ ! -e "$saved" && ! -e "$saved.absent" ]] || return 0
    mkdir -p "$(dirname "$saved")" || return 1
    if [[ -e "$file" ]]; then cp -p -- "$file" "$saved" || return 1; else : > "$saved.absent" || return 1; fi
    printf '%s\n' "$file" >> "$BACKUP_DIR/files.list"
}
restore_files() {
    local file saved owner failed=0
    while IFS= read -r file; do
        saved="$BACKUP_DIR/files/${file#/}"
        if [[ -L "$file" ]]; then log_error "回滚拒绝符号链接: $file"; failed=1; continue; fi
        if [[ -f "$saved.absent" ]]; then
            rm -f -- "$file" || failed=1
        elif [[ -f "$saved" ]]; then
            owner=$(stat -c %U -- "$saved") || { failed=1; continue; }
            # 用户目录中的文件以目标用户身份写回，避免 root cp 跟随检查后被替换的符号链接。
            if [[ "$owner" != root ]]; then
                atomic_write "$file" "$saved" "$(stat -c %a -- "$saved")" "$owner" || failed=1
            else
                cp -p -- "$saved" "$file" || failed=1
            fi
        else
            log_error "缺少备份: $file"; failed=1
        fi
    done < "$BACKUP_DIR/files.list"
    return "$failed"
}
# 用户文件使用目标用户权限写入，不以 root 跟随用户目录中的链接写文件。
atomic_write() {
    local file="$1" payload="$2" mode="${3:-0644}" owner="${4:-}" temp
    [[ ! -L "$file" && ( ! -e "$file" || -f "$file" ) ]] || { log_error "不是普通文件或为链接: $file"; return 1; }
    if [[ -n "$owner" && "$owner" != root ]]; then
        # 在目标用户的 Bash 中展开参数，不能在 root 的调用者 shell 提前展开。
        # shellcheck disable=SC2016
        runuser -u "$owner" -- /bin/bash --noprofile --norc -c '
            set -o pipefail
            file=$1; mode=$2
            [[ ! -L "$file" ]] || exit 1
            temp=$(mktemp "${file}.tmp.XXXXXX") || exit 1
            if cat > "$temp" && chmod "$mode" "$temp" && mv -f -- "$temp" "$file"; then exit 0; fi
            rm -f -- "$temp"; exit 1
        ' _ "$file" "$mode" < "$payload"
        return $?
    fi
    temp=$(mktemp "${file}.tmp.XXXXXX") || return 1
    if install -m "$mode" -- "$payload" "$temp" && mv -f -- "$temp" "$file"; then return 0; fi
    rm -f -- "$temp"
    return 1
}
# 区块缺失结束标记时拒绝修改，避免删除后续用户配置。
# 同时去掉紧邻区块前、由 update_block 插入的那一个空行，保证重复执行不累积空行。
strip_block() {
    local file="$1" begin="$2" end="$3" output="$4"
    [[ -e "$file" ]] || { : > "$output"; return 0; }
    awk -v begin="$begin" -v end="$end" '
        $0 == begin { if (inside || seen++) exit 2; inside=1; held=0; next }
        $0 == end { if (!inside) exit 2; inside=0; ended++; next }
        inside { next }
        held { print ""; held=0 }
        $0 == "" { held=1; next }
        { print }
        END { if (held) print ""; if (inside || seen != ended) exit 2 }
    ' "$file" > "$output"
}
strip_legacy_aliases() {
    local file="$1" output="$2"
    awk '
        $0 == "# Custom aliases - debian12-setup" { if (inside || seen++) exit 2; inside=1; next }
        inside && $0 ~ /^#?alias ports=/ { inside=0; ended++; next }
        !inside { print }
        END { if (inside || seen != ended) exit 2 }
    ' "$file" > "$output"
}
update_block() {
    local file="$1" begin="$2" end="$3" payload="$4" owner="${5:-}" clean result mode=0644
    [[ ! -L "$file" ]] || return 1
    # 保留已有文件权限（如用户自设的 0600 .bashrc），不统一放宽为 0644。
    if [[ -f "$file" ]]; then mode=$(stat -c %a -- "$file") || return 1; fi
    backup_file "$file" || return 1
    clean=$(mktemp "$BACKUP_DIR/clean.XXXXXX") || return 1
    result=$(mktemp "$BACKUP_DIR/result.XXXXXX") || return 1
    strip_block "$file" "$begin" "$end" "$clean" || { log_error "配置区块不完整: $file"; return 1; }
    if [[ "$begin" == "$ALIASES_BEGIN" ]] && grep -q '^# Custom aliases - debian12-setup$' "$clean"; then
        strip_legacy_aliases "$clean" "$result" || { log_error '旧别名区块不完整，请手动检查'; return 1; }
        cp -- "$result" "$clean" || return 1
    fi
    { cat "$clean"; printf '\n%s\n' "$begin"; cat "$payload"; printf '%s\n' "$end"; } > "$result" || return 1
    atomic_write "$file" "$result" "$mode" "$owner"
}
apt_install() { apt_get update && apt_get install -y -- "$@"; }
update_system() {
    local plan upgrade=yes
    log_step '系统更新'
    apt_get update || return 1
    # 先模拟：无变更直接跳过；仅当升级会移除软件包时才列出并确认（Inst/Remv 为 apt 固定输出，不随语言变化）。
    plan=$(apt_get -s full-upgrade) || return 1
    if ! grep -q '^Inst \|^Remv ' <<< "$plan"; then
        log_info '系统已是最新'
        upgrade=no
    elif grep -q '^Remv ' <<< "$plan"; then
        grep '^Remv ' <<< "$plan"
        confirm '以上软件包将在升级中被移除，确认执行？' y || upgrade=no
    fi
    if [[ "$upgrade" == yes ]]; then
        # 已修改的配置（如带本脚本 Include 的 sshd_config）一律保留本地版本，避免升级时选错而静默丢失加固项。
        UCF_FORCE_CONFFOLD=1 apt_get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade -y || return 1
        if [[ -f "$SSH_MANAGED" ]] && ! grep -qxF "$SSH_BEGIN" "$SSH_CONFIG"; then
            log_warn 'sshd_config 中本脚本的 Include 区块已丢失，SSH 加固未生效；请重新执行 SSH 安全配置'
        fi
        log_info '已保留本地修改过的配置文件；维护者新版本通常保存为 *.dpkg-dist / *.ucf-dist，可人工比对'
    fi
    plan=$(apt_get -s autoremove) || return 1
    if grep -q '^Remv ' <<< "$plan"; then
        grep '^Remv ' <<< "$plan"
        if confirm '以上软件包已不再需要，确认清理？' y; then apt_get autoremove -y || return 1; fi
    fi
    apt_get autoclean || return 1
    [[ ! -f /var/run/reboot-required ]] || log_warn '系统提示需要重启，请安排维护窗口'
}
install_docker() {
    local package distro codename temp source_file=/etc/apt/sources.list.d/docker.list
    local key_file=/etc/apt/keyrings/docker.asc conflicts=()
    # Docker 官方 APT 签名密钥指纹（Debian/Ubuntu 共用）；官方轮换密钥时需同步更新此值。
    local docker_fpr=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
    log_step '安装 Docker（官方源）'
    if command -v docker >/dev/null 2>&1; then
        docker --version || return 1
        confirm 'Docker 已安装，是否更新官方安装？' || return 0
    fi
    # 源路径按检测到的发行版选择（linux/debian 或 linux/ubuntu），不混用。
    distro="$OS_ID"; codename="$OS_CODENAME"
    [[ ( "$distro" == debian || "$distro" == ubuntu ) && "$codename" =~ ^[a-z]+$ ]] || { log_error '发行版信息无效'; return 1; }
    for package in docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc; do
        if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" == 'install ok installed' ]]; then conflicts+=("$package"); fi
    done
    if (( ${#conflicts[@]} )); then
        log_error "存在冲突包: ${conflicts[*]}。请先评估现有容器并手动迁移，不自动卸载。"
        return 1
    fi
    # 不叠加另一份 Signed-By 不同的软件源。只检查 apt 实际加载的 .list/.sources，忽略 .save/.distUpgrade 等残留。
    if { grep -rlE --include='*.list' --include='*.sources' 'download\.docker\.com/linux/(debian|ubuntu)' /etc/apt/sources.list.d 2>/dev/null
         grep -lE 'download\.docker\.com/linux/(debian|ubuntu)' /etc/apt/sources.list 2>/dev/null; true; } | grep -vxF "$source_file"; then
        log_error '存在其他 Docker 源，请先统一源与 Signed-By 配置'; return 1
    fi
    apt_install ca-certificates curl gnupg || return 1
    start_change || return 1
    install -d -m 0755 /etc/apt/keyrings || return 1
    backup_file "$key_file" && backup_file "$source_file" || return 1
    temp=$(mktemp "$BACKUP_DIR/docker-key.XXXXXX") || return 1
    if ! curl -fsSL --connect-timeout 15 --max-time 120 --retry 3 "https://download.docker.com/linux/$distro/gpg" -o "$temp" ||
        ! gpg --batch --show-keys "$temp" >/dev/null; then
        log_error '下载或校验 Docker GPG 密钥失败，请检查网络/代理'; return 1
    fi
    if ! gpg --batch --with-colons --show-keys "$temp" 2>/dev/null | awk -F: '$1 == "fpr" {print $10}' | grep -qxF "$docker_fpr"; then
        log_error "Docker GPG 密钥指纹不是 ${docker_fpr}；可能遭中间人篡改或官方已轮换密钥，请人工核对 docs.docker.com"
        return 1
    fi
    atomic_write "$key_file" "$temp" || return 1
    printf 'deb [arch=%s signed-by=%s] https://download.docker.com/linux/%s %s stable\n' "$(dpkg --print-architecture)" "$key_file" "$distro" "$codename" > "$temp" || { restore_files; return 1; }
    atomic_write "$source_file" "$temp" || { restore_files; return 1; }
    if ! apt_get update; then restore_files || log_error '源回滚失败'; return 1; fi
    apt_get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || return 1
    systemctl enable --now docker && docker --version && docker compose version || return 1
    log_warn 'Docker 发布端口可能绕过 UFW；请按实际防火墙后端检查外部可达性。'
}
create_user() {
    local username
    log_step '新建用户'
    ask '用户名: ' username || return 1
    [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]] || { log_error '用户名格式无效'; return 1; }
    if id -- "$username" >/dev/null 2>&1; then
        log_warn "用户 $username 已存在，保留现有账号"
        # 上次可能在 passwd 处失败：账号已建但未设密码、未加组。允许补全，而不是直接跳过。
        confirm '是否继续为该用户补设密码/组？' || return 0
        if [[ "$(passwd -S -- "$username" 2>/dev/null | awk '{print $2}')" =~ ^(L|NP)$ ]]; then
            log_warn '该账号当前无可用密码，sudo 将无法验证'
            if confirm '现在设置密码？' y; then passwd "$username" || return 1; fi
        fi
    else
        useradd -m -s /bin/bash -- "$username" || return 1
        passwd "$username" || { log_error "账号已创建但密码未设置；重新执行此步骤可补设"; return 1; }
    fi
    if confirm '是否允许此用户使用 sudo？' y; then
        command -v sudo >/dev/null 2>&1 || apt_install sudo || return 1
        usermod -aG sudo -- "$username" || return 1
    fi
    if command -v docker >/dev/null 2>&1; then
        log_warn 'docker 组具有接近 root 的系统权限，不是普通低权限组。'
        if confirm '是否仍加入 docker 组？'; then usermod -aG docker -- "$username" || return 1; fi
    fi
}
add_ssh_key() {
    local username home auth_keys temp staged line key_type key_body rest count ended=no
    log_step '添加 SSH 公钥'
    ask '用户名: ' username && validate_user "$username" || return 1
    home=$(user_home "$username") || return 1
    [[ "$home" == /* && -d "$home" && ! -L "$home" && ! -L "$home/.ssh" && ! -L "$home/.ssh/authorized_keys" ]] || { log_error '用户 home/.ssh 不安全或不存在'; return 1; }
    require_commands ssh-keygen runuser || return 1
    start_change || return 1
    temp=$(mktemp "$BACKUP_DIR/keys.XXXXXX") || return 1
    log_info '每行一把公钥；输入 END 结束。不接受私钥和 authorized_keys 选项。'
    while IFS= read -r line; do
        if [[ "$line" == END || "$line" == end ]]; then ended=yes; break; fi
        [[ -n "$line" ]] || continue
        read -r key_type key_body rest <<< "$line"
        case "$key_type" in
            ssh-ed25519|ssh-rsa|ecdsa-sha2-*|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|*-cert-v01@openssh.com) ;;
            *)
                if [[ "$line" =~ [[:space:]](ssh-|ecdsa-|sk-) ]]; then log_error '不接受带 authorized_keys 选项的行，请只粘贴“算法 公钥 注释”'
                else log_error '不是受支持的公钥行'; fi
                return 1 ;;
        esac
        [[ "$key_body" =~ ^[a-zA-Z0-9+/]+={0,3}$ ]] || { log_error '公钥数据格式无效'; return 1; }
        printf '%s\n' "$line" > "$BACKUP_DIR/one-key"
        ssh-keygen -l -f "$BACKUP_DIR/one-key" >/dev/null 2>&1 || { log_error '公钥内容无效'; return 1; }
        printf '%s\n' "$line" >> "$temp" || return 1
    done
    [[ "$ended" == yes ]] || { log_warn '输入未以 END 结束，未写入公钥'; return 1; }
    [[ -s "$temp" ]] || { log_error '没有有效公钥'; return 1; }
    runuser -u "$username" -- mkdir -p -m 0700 -- "$home/.ssh" || return 1
    runuser -u "$username" -- chmod 0700 -- "$home/.ssh" || return 1
    auth_keys="$home/.ssh/authorized_keys"
    backup_file "$auth_keys" || return 1
    staged=$(mktemp "$BACKUP_DIR/authorized-keys.XXXXXX") || return 1
    # 保留带选项的已有行；只按新公钥的算法+数据去重。awk 总会补齐末尾换行。
    awk 'FILENAME == ARGV[1] { print; if ($0 !~ /^[[:space:]]*#/) for (i=1;i<NF;i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) {seen[$i " " $(i+1)]=1; break} next }
         !seen[$1 " " $2]++ { print }' /dev/null "$temp" > "$staged" || return 1
    if [[ -f "$auth_keys" ]]; then
        awk 'FILENAME == ARGV[1] { print; if ($0 !~ /^[[:space:]]*#/) for (i=1;i<NF;i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) {seen[$i " " $(i+1)]=1; break} next }
             !seen[$1 " " $2]++ { print }' "$auth_keys" "$temp" > "$staged" || return 1
    fi
    atomic_write "$auth_keys" "$staged" 0600 "$username" || return 1
    count=$(ssh-keygen -l -f "$auth_keys" 2>/dev/null | wc -l) || return 1
    log_info "已保存公钥，当前可解析密钥数: ${count}；请在第二终端验证登录。"
}
install_common_tools() {
    local packages=(vim git curl wget htop iproute2 net-tools tree unzip zip tmux ncdu iotop sysstat lsof bind9-dnsutils tcpdump)
    log_step '安装常用工具'
    # dig/nslookup：Debian 13、Ubuntu 26.04 已移除过渡包 dnsutils，统一用各版本都提供的 bind9-dnsutils。
    # sudo：Ubuntu 25.10+ 默认是 sudo-rs；已有 sudo 命令时不装 sudo 包，避免替换系统默认实现。
    command -v sudo >/dev/null 2>&1 || packages+=(sudo)
    confirm '安装 vim/git/curl/htop/tmux/网络工具/sudo 等常用软件？' y || return 0
    apt_install "${packages[@]}"
}
current_timezone() {
    local timezone
    timezone=$(timedatectl show -p Timezone --value 2>/dev/null)
    [[ -n "$timezone" ]] || timezone=$(readlink /etc/localtime 2>/dev/null | sed 's|^.*/zoneinfo/||')
    printf '%s\n' "${timezone:-UTC}"
}
configure_timezone() {
    local timezone current
    log_step '时区'
    current=$(current_timezone)
    ask "时区 [${current}]: " timezone || return 1
    timezone="${timezone:-$current}"
    [[ "$timezone" != /* && "$timezone" != *..* && -f "/usr/share/zoneinfo/$timezone" ]] || { log_error '无效时区'; return 1; }
    [[ "$timezone" != "$current" ]] || { log_info "保持当前时区 ${current}"; return 0; }
    confirm "设置时区为 ${timezone}？" y || return 0
    timedatectl set-timezone "$timezone"
}
# /proc/swaps 列：Filename Type Size Used Priority（单位 KiB）。
swap_active() { awk -v f="$1" 'NR > 1 && $1 == f {found=1} END {exit !found}' /proc/swaps 2>/dev/null; }
swap_managed() { [[ -f "$FSTAB" ]] && grep -qxF "$SWAP_BEGIN" "$FSTAB"; }
fmt_mib() { awk -v m="$1" 'BEGIN {if (m >= 1024) printf "%.1fG", m / 1024; else printf "%dM", m}'; }
# 1024 / 1024M / 2G → MiB
parse_size_mib() {
    [[ "$1" =~ ^([0-9]{1,7})([MmGg]?)$ ]] || return 1
    if [[ "${BASH_REMATCH[2],,}" == g ]]; then printf '%d\n' $(( 10#${BASH_REMATCH[1]} * 1024 )); else printf '%d\n' $(( 10#${BASH_REMATCH[1]} )); fi
}
# swapoff 要把该 swap 中的页全部换回内存；可用内存不足时会触发 OOM，先检查并留 128MiB 余量。
swap_can_disable() {
    local used avail
    swap_active "$1" || return 0
    used=$(awk -v f="$1" 'NR > 1 && $1 == f {print $4}' /proc/swaps)
    avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    valid_uint "$used" 0 4294967295 && valid_uint "$avail" 0 4294967295 || { log_error '无法读取 swap 用量或可用内存'; return 1; }
    (( 10#$used + 131072 <= 10#$avail )) || { log_error "$1 已使用 $(( 10#$used / 1024 ))MiB，可用内存 $(( 10#$avail / 1024 ))MiB 不足以安全停用；请先释放内存"; return 1; }
}
write_swap_fstab() {
    local temp
    temp=$(mktemp "$BACKUP_DIR/fstab.XXXXXX") || return 1
    if [[ "$1" == add ]]; then
        printf '%s none swap sw 0 0\n' "$SWAP_FILE" > "$temp" && update_block "$FSTAB" "$SWAP_BEGIN" "$SWAP_END" "$temp" || return 1
    else
        backup_file "$FSTAB" || return 1
        strip_block "$FSTAB" "$SWAP_BEGIN" "$SWAP_END" "$temp" || { log_error "配置区块不完整: $FSTAB"; return 1; }
        atomic_write "$FSTAB" "$temp" "$(stat -c %a -- "$FSTAB")" || return 1
    fi
    # fstab 中的 swap 由 systemd-fstab-generator 生成 .swap 单元，需重新生成。
    systemctl daemon-reload
}
create_swap_file() {
    # noclobber 保证新建而不是写入已存在的文件/链接；swap 可能含内存中的敏感数据，先收紧权限再分配空间。
    ( umask 077; set -C; : > "$SWAP_FILE" ) || return 1
    # fallocate 在 ext4/xfs 上生成无空洞文件；失败时退回 dd 逐块写零（较慢）。
    if ! fallocate -l "${1}MiB" -- "$SWAP_FILE" 2>/dev/null; then
        log_warn 'fallocate 失败，改用 dd 写零（较慢）'
        dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$1" conv=fsync status=progress || return 1
    fi
    mkswap -- "$SWAP_FILE" >/dev/null && swapon -- "$SWAP_FILE"
}
setup_swap_file() {
    local fs dir mem current=0 avail max default input size recreate=yes current_swappiness swappiness others temp
    dir=$(dirname "$SWAP_FILE")
    fs=$(stat -f -c %T -- "$dir") || return 1
    # stat 对 ext4 也显示 ext2/ext3。btrfs 需禁用 CoW/压缩，不在此自动处理。
    case "$fs" in
        ext2/ext3|xfs) ;;
        btrfs) log_error 'btrfs 上的 swap 文件需禁用 CoW（可用 btrfs filesystem mkswapfile），本脚本不自动处理'; return 1 ;;
        *) log_error "不支持在 ${fs} 文件系统上自动创建 swap 文件"; return 1 ;;
    esac
    mem=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo)
    valid_uint "$mem" 1 2147483647 || { log_error '无法读取物理内存容量'; return 1; }
    [[ ! -f "$SWAP_FILE" ]] || current=$(( $(stat -c %s -- "$SWAP_FILE") / 1048576 ))
    avail=$(df -P -m -- "$dir" | awk 'NR == 2 {print $4}')
    valid_uint "$avail" 0 2147483647 || { log_error '无法读取磁盘可用空间'; return 1; }
    # 调整大小时旧文件会先删除，其空间计入可用。
    max=$(( 10#$avail + current - SWAP_RESERVE_MIB ))
    (( max >= SWAP_MIN_MIB )) || { log_error "磁盘可用 ${avail}MiB，保留 ${SWAP_RESERVE_MIB}MiB 后不足以创建 swap"; return 1; }
    # 推荐值：内存 <2G 取 2 倍，2–8G 与内存相同，≥8G 取 4G（不考虑休眠）；按 256MiB 向上取整，受磁盘上限约束。
    if (( mem < 2048 )); then default=$(( mem * 2 )); elif (( mem < 8192 )); then default=$mem; else default=4096; fi
    default=$(( (default + 255) / 256 * 256 ))
    (( default <= max )) || default=$(( max / 256 * 256 ))
    (( default >= SWAP_MIN_MIB )) || default=$max
    log_info "物理内存 ${mem}MiB；${dir} 可用 ${avail}MiB，可分配上限 ${max}MiB（保留 ${SWAP_RESERVE_MIB}MiB）"
    ask "swap 大小（如 1024M、2G）[${default}M]: " input || return 1
    size=$(parse_size_mib "${input:-${default}M}") || { log_error '格式无效，示例：1024M、2G'; return 1; }
    (( size >= SWAP_MIN_MIB && size <= max )) || { log_error "大小须在 ${SWAP_MIN_MIB}–${max}MiB 之间"; return 1; }
    if (( current == size )) && swap_active "$SWAP_FILE"; then recreate=no; log_info "${SWAP_FILE} 已是 ${size}MiB 且已启用，不重建"; fi
    [[ "$recreate" == no ]] || swap_can_disable "$SWAP_FILE" || return 1
    current_swappiness=$(sysctl -n vm.swappiness) || return 1
    log_info 'vm.swappiness 越低越倾向把页留在内存；把 swap 当作防 OOM 兜底时常用 10'
    ask "vm.swappiness（0–100）[${current_swappiness}]: " swappiness || return 1
    swappiness="${swappiness:-$current_swappiness}"
    valid_uint "$swappiness" 0 100 || { log_error 'vm.swappiness 须为 0–100 的整数'; return 1; }
    swappiness=$((10#$swappiness))
    [[ "$recreate" == yes || "$swappiness" != "$current_swappiness" ]] || { log_info '没有需要变更的内容'; return 0; }
    if [[ "$recreate" == yes ]]; then
        if (( current > 0 )); then printf 'swap 文件: %s %sMiB -> %sMiB（先停用并删除旧文件）\n' "$SWAP_FILE" "$current" "$size"
        else printf 'swap 文件: %s 新建 %sMiB，写入 %s\n' "$SWAP_FILE" "$size" "$FSTAB"; fi
    fi
    [[ "$swappiness" == "$current_swappiness" ]] || printf 'vm.swappiness: %s -> %s（%s）\n' "$current_swappiness" "$swappiness" "$SWAP_SYSCTL"
    confirm '确认执行？' || return 0
    # 停用→删除→创建→写 fstab 期间忽略中断/断线；由 main/run_all 在步骤返回后恢复。
    trap '' HUP INT TERM
    start_change || return 1
    if [[ "$swappiness" != "$current_swappiness" ]]; then
        others=$(grep -lsE '^[[:space:]]*vm[./]swappiness[[:space:]]*=' /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf | grep -vxF "$SWAP_SYSCTL")
        [[ -z "$others" ]] || log_warn "以下文件也设置了 vm.swappiness，重启后可能覆盖本设置: ${others//$'\n'/, }"
        mkdir -p "$(dirname "$SWAP_SYSCTL")" && backup_file "$SWAP_SYSCTL" || return 1
        temp=$(mktemp "$BACKUP_DIR/swap-sysctl.XXXXXX") || return 1
        printf '# Managed by properties-script\nvm.swappiness = %s\n' "$swappiness" > "$temp" || return 1
        if ! atomic_write "$SWAP_SYSCTL" "$temp" || ! sysctl -q -w "vm.swappiness=$swappiness"; then
            restore_files; sysctl -q -w "vm.swappiness=$current_swappiness"; return 1
        fi
    fi
    if [[ "$recreate" == yes ]]; then
        if swap_active "$SWAP_FILE"; then swapoff -- "$SWAP_FILE" || return 1; fi
        rm -f -- "$SWAP_FILE" || return 1
        if ! create_swap_file "$size" || ! write_swap_fstab add; then
            log_error 'swap 创建失败，清理半成品并移除 fstab 中本脚本的条目'
            if swap_active "$SWAP_FILE"; then swapoff -- "$SWAP_FILE"; fi
            rm -f -- "$SWAP_FILE"
            write_swap_fstab remove || log_error "请人工检查 ${FSTAB}，备份: $BACKUP_DIR"
            return 1
        fi
    fi
    swapon --show
    log_info "swap 配置完成；备份: $BACKUP_DIR"
}
remove_swap_file() {
    swap_managed || { log_info '本脚本未创建过 swap，无需删除'; return 0; }
    swap_can_disable "$SWAP_FILE" || return 1
    confirm "确认停用并删除 ${SWAP_FILE}？" || return 0
    trap '' HUP INT TERM
    start_change || return 1
    if swap_active "$SWAP_FILE"; then swapoff -- "$SWAP_FILE" || return 1; fi
    if ! write_swap_fstab remove; then
        log_error "更新 ${FSTAB} 失败，重新启用 swap"
        restore_files && systemctl daemon-reload; swapon -- "$SWAP_FILE"
        return 1
    fi
    rm -f -- "$SWAP_FILE" || return 1
    log_info "已删除；备份: $BACKUP_DIR"
    [[ ! -f "$SWAP_SYSCTL" ]] || log_info "vm.swappiness 设置（${SWAP_SYSCTL}）保留；没有 swap 时不起作用"
}
configure_swap() {
    local action
    log_step '虚拟内存（swap 文件）'
    require_commands mkswap swapon swapoff fallocate df sysctl || return 1
    if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container --quiet; then
        log_error '检测到容器（如 OpenVZ/LXC），swap 由宿主机分配，无法在容器内创建'; return 1
    fi
    [[ -r /proc/swaps ]] || { log_error '内核未提供 /proc/swaps'; return 1; }
    if awk 'NR > 1 {found=1} END {exit !found}' /proc/swaps; then swapon --show; else log_info '当前没有启用的 swap'; fi
    printf 'vm.swappiness = %s\n' "$(sysctl -n vm.swappiness)"
    if [[ -L "$SWAP_FILE" || ( -e "$SWAP_FILE" && ! -f "$SWAP_FILE" ) ]]; then log_error "$SWAP_FILE 不是普通文件"; return 1; fi
    if [[ -e "$SWAP_FILE" ]] && ! swap_managed; then
        log_error "$SWAP_FILE 已存在但不由本脚本管理；请先人工 swapoff 并删除它及 fstab 条目"; return 1
    fi
    if [[ -f "$FSTAB" ]] && awk -v b="$SWAP_BEGIN" -v e="$SWAP_END" -v f="$SWAP_FILE" '$0 == b {i=1; next} $0 == e {i=0; next} !i && $1 == f {found=1} END {exit !found}' "$FSTAB"; then
        log_error "$FSTAB 中已有非本脚本管理的 $SWAP_FILE 条目，请先人工处理"; return 1
    fi
    ask '1=创建/调整大小，2=删除本脚本创建的 swap，0=返回: ' action || return 1
    case "$action" in
        0) return 0 ;;
        1) setup_swap_file ;;
        2) remove_swap_file ;;
        *) log_error '选择无效'; return 1 ;;
    esac
}
# socket 激活或 ssh.service 未运行时 /run/sshd 可能不存在，sshd -t/-T 会报 Missing privilege separation directory。
prepare_sshd() { [[ -d /run/sshd ]] || install -d -m 0755 /run/sshd; }
ssh_effective() { prepare_sshd && sshd -T -f "$SSH_CONFIG" "$@"; }
ssh_ports() { ssh_effective | awk '$1 == "port" {print $2}' | sort -nu; }
# 合并实际 sshd/socket 入口和当前连接，避免 console 操作时误放行默认 22。
# socket 激活时 sshd 使用 systemd 传入的监听，忽略 sshd_config 的 Port（Debian），或由生成器据此生成 socket 监听（Ubuntu），
# 两种情况都以 socket 的 Listen 为准，不把未监听的 Port 计入防火墙/Fail2ban。
ssh_entry_ports() {
    local ports='' unit listeners token connection_port live socket_mode=no
    for unit in ssh.socket sshd.socket; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            listeners=$(systemctl show -p Listen --value "$unit") || return 1
            [[ -n "$listeners" ]] || return 1
            for token in $listeners; do
                [[ "$token" != '(Stream)' ]] || continue
                valid_port "${token##*:}" || { log_error '无法识别 SSH socket 入口'; return 1; }
                ports+="${token##*:}"$'\n'
            done
            socket_mode=yes
            break
        fi
    done
    if [[ "$socket_mode" == no ]]; then ports=$(ssh_ports) || return 1; fi
    live=$(ss -H -ltnp | awk '/"sshd"/ {p=$4; sub(/^.*:/,"",p); if(p ~ /^[0-9]+$/) print p}') || return 1
    [[ -z "$live" ]] || ports+=$'\n'"$live"
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        read -r _ _ _ connection_port <<< "$SSH_CONNECTION"
        valid_port "$connection_port" || return 1
        ports+=$'\n'"$connection_port"
    fi
    printf '%s\n' "$ports" | awk 'NF' | sort -nu
}
port_is_listening() { ss -H -ltn | awk -v port="$1" '{p=$4; sub(/^.*:/,"",p); if(p == port) found=1} END {exit !found}'; }
ufw_active() { command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status | grep -x 'Status: active' >/dev/null; }
configure_ufw() {
    local ports port custom
    log_step '配置 UFW'
    require_commands sshd ss || return 1
    ports=$(ssh_entry_ports) || return 1
    if ! command -v ufw >/dev/null 2>&1; then apt_install ufw || return 1; fi
    log_warn '不会删除已有规则；Docker 发布端口和云安全组必须另外核查。'
    log_info "将保留配置/当前连接的 SSH 端口: ${ports//$'\n'/,}"
    confirm '确认设置默认拒绝入站、允许出站并放行上述 SSH 端口？' || return 0
    for port in $ports; do valid_port "$port" && ufw allow "$port/tcp" comment SSH || return 1; done
    ufw default deny incoming && ufw default allow outgoing || return 1
    if confirm '开放 HTTP/HTTPS？'; then ufw allow 80/tcp && ufw allow 443/tcp || return 1; fi
    while true; do
        ask '其他端口（8080/tcp、8080/udp；空白结束）: ' custom || return 1
        [[ -n "$custom" ]] || break
        if ! [[ "$custom" =~ ^([0-9]{1,5})(/(tcp|udp))?$ ]] || ! valid_port "${BASH_REMATCH[1]}"; then log_error '端口格式无效'; continue; fi
        [[ "$custom" == */* ]] || custom+=/tcp
        ufw allow "$custom" || return 1
    done
    confirm '确认启用 UFW？' || return 0
    ufw --force enable && ufw status verbose || return 1
    configure_ufw_docker
}
# Docker 的 DNAT 发生在 INPUT 之前，发布端口走 FORWARD，绕过 UFW 入站规则。
# 采用 ufw-docker 的通用做法：DOCKER-USER 先交给 ufw-user-forward（即 ufw route 规则），
# 来自私有网段的流量放行，其余发往容器私有地址的新连接丢弃。只覆盖 IPv4。
write_ufw_docker_payload() {
    cat <<'RULES'
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12
-A DOCKER-USER -j RETURN
-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP
COMMIT
RULES
}
configure_ufw_docker() {
    local action temp custom
    command -v docker >/dev/null 2>&1 || return 0
    if ! iptables -S DOCKER-USER >/dev/null 2>&1; then
        log_warn '未检测到 DOCKER-USER 链（Docker 未运行或使用 nftables 后端），无法让 UFW 管控 Docker 发布端口'; return 0
    fi
    log_warn 'Docker 发布端口默认绕过 UFW 入站规则，外部可直接访问。'
    ask 'UFW 管控 Docker 发布端口：1=启用/更新，2=移除，0=跳过: ' action || return 1
    case "$action" in 0) return 0 ;; 1|2) ;; *) log_error '选择无效'; return 1 ;; esac
    if [[ "$action" == 1 ]]; then
        log_warn '启用后，外部访问容器须按“容器内端口”放行，例如 -p 8080:80 需执行: ufw route allow proto tcp from any to any port 80'
        confirm '确认启用？未放行的发布端口将对外不可达' || return 0
    elif ! grep -qxF "$UFW_DOCKER_BEGIN" "$UFW_AFTER_RULES"; then
        log_info '未启用过，无需移除'; return 0
    fi
    start_change || return 1
    temp=$(mktemp "$BACKUP_DIR/ufw-docker.XXXXXX") || return 1
    if [[ "$action" == 1 ]]; then
        write_ufw_docker_payload > "$temp" && update_block "$UFW_AFTER_RULES" "$UFW_DOCKER_BEGIN" "$UFW_DOCKER_END" "$temp" || { restore_files; return 1; }
    else
        backup_file "$UFW_AFTER_RULES" || return 1
        strip_block "$UFW_AFTER_RULES" "$UFW_DOCKER_BEGIN" "$UFW_DOCKER_END" "$temp" || { log_error "配置区块不完整: $UFW_AFTER_RULES"; return 1; }
        atomic_write "$UFW_AFTER_RULES" "$temp" "$(stat -c %a -- "$UFW_AFTER_RULES")" || return 1
    fi
    if ! ufw reload; then
        log_error 'UFW 加载失败，恢复 after.rules'
        restore_files && ufw reload || log_error "回滚后 UFW 仍加载失败，请检查: $BACKUP_DIR"
        return 1
    fi
    if [[ "$action" == 2 ]]; then
        # 区块移除后 ufw reload 不再管理 DOCKER-USER，需清空已加载的旧规则；Docker 不依赖其中内容。
        iptables -F DOCKER-USER && { iptables -F ufw-docker-logging-deny && iptables -X ufw-docker-logging-deny; } 2>/dev/null
        log_info '已移除；Docker 发布端口恢复为绕过 UFW。已有 ufw route 规则未删除。'
        return 0
    fi
    while true; do
        ask '放行的容器内端口（80/tcp、53/udp；空白结束）: ' custom || return 1
        [[ -n "$custom" ]] || break
        if ! [[ "$custom" =~ ^([0-9]{1,5})(/(tcp|udp))?$ ]] || ! valid_port "${BASH_REMATCH[1]}"; then log_error '端口格式无效'; continue; fi
        [[ "$custom" == */* ]] || custom+=/tcp
        ufw route allow proto "${custom#*/}" from any to any port "${custom%/*}" || return 1
    done
    log_info "已启用；备份: ${BACKUP_DIR}。日志前缀 [UFW DOCKER BLOCK]。IPv6 容器网络不在管控范围内。"
}
detect_ssh_units() {
    local unit
    SSH_SERVICE=; SSH_SOCKET=; SSH_SOCKET_FILE=; SSH_SOCKET_LISTENERS=
    for unit in ssh.service sshd.service; do
        if [[ "$(systemctl show -p LoadState --value "$unit" 2>/dev/null)" == loaded ]]; then SSH_SERVICE="$unit"; break; fi
    done
    [[ -n "$SSH_SERVICE" ]] || { log_error '未找到 SSH 服务'; return 1; }
    for unit in ssh.socket sshd.socket; do
        if systemctl is-active --quiet "$unit"; then
            SSH_SOCKET="$unit"
            SSH_SOCKET_LISTENERS=$(systemctl show -p Listen --value "$unit") || return 1
            [[ -n "$SSH_SOCKET_LISTENERS" ]] || return 1
            SSH_SOCKET_FILE="$SYSTEMD_UNIT_ROOT/$unit.d/90-properties-script.conf"
            break
        fi
    done
}
reload_ssh() {
    if [[ -n "$SSH_SOCKET" ]]; then
        # 服务仍在运行时 systemd 拒绝重新监听 socket（"Socket service ... already active, refusing"），
        # 服务随即退回独立监听；必须先停服务再重启 socket。KillMode=process 保证已有会话不断开。
        systemctl daemon-reload && systemctl stop "$SSH_SERVICE" && systemctl restart "$SSH_SOCKET" && systemctl start "$SSH_SERVICE"
    else
        systemctl reload "$SSH_SERVICE"
    fi
}
sync_fail2ban_ports() {
    local ports temp
    [[ -f "$FAIL2BAN_CONFIG" ]] || {
        if command -v fail2ban-client >/dev/null 2>&1; then log_warn '已有非本脚本管理的 Fail2ban jail，请人工同步 SSH 端口'; fi
        return 0
    }
    ports=$(ssh_entry_ports | paste -sd, -) || return 1
    backup_file "$FAIL2BAN_CONFIG" || return 1
    temp=$(mktemp "$BACKUP_DIR/f2b-sync.XXXXXX") || return 1
    awk -v ports="$ports" '/^port[[:space:]]*=/ {$0="port = " ports} {print}' "$FAIL2BAN_CONFIG" > "$temp" || return 1
    atomic_write "$FAIL2BAN_CONFIG" "$temp" && fail2ban-client -t && systemctl restart fail2ban && wait_fail2ban || return 1
}
rollback_ssh() {
    log_warn "恢复 SSH/套接字/Fail2ban 配置，备份: $BACKUP_DIR"
    restore_files || { log_error '文件回滚失败，请使用控制台和备份恢复'; return 1; }
    if ! sshd -t -f "$SSH_CONFIG" || ! reload_ssh; then log_error 'SSH 回滚加载失败'; return 1; fi
    if [[ -f "$FAIL2BAN_CONFIG" ]]; then systemctl restart fail2ban || return 1; fi
}
configure_ssh() {
    local new_port old_ports ports port admin_user='' disable_root=no disable_password=no extra=no
    local temp main_clean expected config actual key attempt listener type root_shell client_ip
    local socket_tokens=()
    log_step 'SSH 安全配置（端口迁移保留旧入口）'
    require_commands sshd ss ssh-keygen || return 1
    prepare_sshd && sshd -t -f "$SSH_CONFIG" && detect_ssh_units || return 1
    old_ports=$(ssh_entry_ports) || return 1
    [[ -n "$old_ports" ]] || return 1
    log_info "配置/当前连接的 SSH 端口: ${old_ports//$'\n'/,}"
    ask '新增 SSH 端口（留空不改；旧端口不会自动关闭）: ' new_port || return 1
    if [[ -n "$new_port" ]]; then
        valid_port "$new_port" || { log_error '端口范围必须为 1–65535'; return 1; }
        new_port=$((10#$new_port))
        if port_is_listening "$new_port" && ! grep -qxF "$new_port" <<< "$old_ports"; then log_error '新端口已被占用'; return 1; fi
    fi
    if confirm '禁用 root 直接登录？'; then disable_root=yes; fi
    if confirm '仅允许公钥认证（关闭密码及 keyboard-interactive，可能影响 MFA）？'; then disable_password=yes; fi
    if [[ "$disable_root" == yes || "$disable_password" == yes ]]; then
        ask '已验证公钥登录且能够 sudo -i 的普通管理员用户名: ' admin_user && validate_user "$admin_user" || return 1
        [[ "$admin_user" != root ]] || { log_error '必须保留非 root 管理员'; return 1; }
        require_commands sudo || return 1
        # sudo -l -U 对无权限用户也返回 0；必须带命令检查能否以 root 运行登录 shell（即 sudo -i）。
        root_shell=$(getent passwd root | awk -F: 'NR == 1 {print $7}')
        sudo -n -l -U "$admin_user" -- "${root_shell:-/bin/bash}" >/dev/null 2>&1 || { log_error "该用户没有可验证的 sudo -i 授权: $admin_user"; return 1; }
        confirm '确认已在第二个终端用公钥登录此用户并成功执行 sudo -i，且控制台可用？' || return 0
    fi
    if confirm '禁用空密码/X11，并设置 MaxAuthTries=3？'; then extra=yes; fi
    if [[ -n "$new_port" && ! -f "$FAIL2BAN_CONFIG" ]] && command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban; then
        log_warn '现有 Fail2ban jail 不由本脚本管理，无法安全自动修改。'
        confirm '确认将人工同步已有 jail 到新端口？否则请先运行本脚本的 Fail2ban 配置' || return 0
    fi
    confirm '确认写入并加载配置？旧入口和 UFW 规则将保留。' || return 0
    if [[ -n "$SSH_SOCKET" && "$(systemctl show -p KillMode --value "$SSH_SERVICE")" != process ]]; then
        log_error 'socket 模式需要重启服务，但当前 KillMode 不能保证保留会话，请通过控制台处理'; return 1
    fi
    # 写入→加载→验证→回滚期间忽略断线/中断，避免停在“文件已改但未验证/未回滚”的中间态。
    # 由 main/run_all 在步骤返回后恢复默认信号处理。
    log_info '进入关键阶段：期间忽略 Ctrl-C 与断线信号，失败会自动回滚'
    trap '' HUP INT TERM
    start_change || return 1
    backup_file "$SSH_CONFIG" && backup_file "$SSH_MANAGED" || return 1
    temp=$(mktemp "$BACKUP_DIR/ssh-managed.XXXXXX") && main_clean=$(mktemp "$BACKUP_DIR/ssh-main.XXXXXX") || return 1
    # 基于现有脚本专属配置增量更新，不丢失此前选择的加固项。
    if [[ -f "$SSH_MANAGED" ]]; then cat "$SSH_MANAGED" > "$temp" || return 1; else : > "$temp"; fi
    ports="$old_ports"
    if [[ -n "$new_port" ]]; then ports=$(printf '%s\n%s\n' "$old_ports" "$new_port" | sort -nu) || return 1; fi
    config=$(mktemp "$BACKUP_DIR/ssh-desired.XXXXXX") || return 1
    awk '!/^[[:space:]]*Port[[:space:]]/' "$temp" > "$config" || return 1
    for port in $ports; do printf 'Port %s\n' "$port" >> "$config" || return 1; done
    # 新选择的单值配置必须放在专属文件最前面。
    : > "$temp" || return 1
    if [[ "$disable_root" == yes ]]; then printf 'PermitRootLogin no\n' >> "$temp" || return 1; fi
    if [[ "$disable_password" == yes ]]; then printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAuthenticationMethods publickey\n' >> "$temp" || return 1; fi
    if [[ "$extra" == yes ]]; then printf 'PermitEmptyPasswords no\nX11Forwarding no\nMaxAuthTries 3\n' >> "$temp" || return 1; fi
    awk 'FILENAME == ARGV[1] {selected[tolower($1)]=1; next} !selected[tolower($1)] {print}' "$temp" "$config" > "$main_clean" || return 1
    cat "$main_clean" >> "$temp" || return 1
    strip_block "$SSH_CONFIG" "$SSH_BEGIN" "$SSH_END" "$main_clean" || return 1
    { printf '%s\nInclude %s\n%s\n' "$SSH_BEGIN" "$SSH_MANAGED" "$SSH_END"; cat "$main_clean"; } > "$config" || return 1
    if ! atomic_write "$SSH_MANAGED" "$temp" 0600 || ! atomic_write "$SSH_CONFIG" "$config"; then restore_files; return 1; fi
    if ! sshd -t -f "$SSH_CONFIG"; then restore_files; return 1; fi
    expected=$(mktemp "$BACKUP_DIR/ssh-effective.XXXXXX") || { restore_files; return 1; }
    # Match Host 匹配的是“客户端”主机名；默认 UseDNS no 时即客户端地址，不能传服务器自己的 hostname。
    client_ip=${SSH_CONNECTION%% *}
    client_ip="${client_ip:-127.0.0.1}"
    if [[ -n "$admin_user" ]]; then
        ssh_effective -C "user=$admin_user,host=$client_ip,addr=$client_ip" > "$expected" || { restore_files; return 1; }
    else
        ssh_effective > "$expected" || { restore_files; return 1; }
    fi
    if [[ "$disable_root" == yes ]] && ! grep -qx 'permitrootlogin no' "$expected"; then log_error 'Match/Include 阻止 root 加固生效'; restore_files; return 1; fi
    if [[ "$disable_root" == yes ]]; then
        ssh_effective -C "user=root,host=$client_ip,addr=$client_ip" > "$config" || { restore_files; return 1; }
        grep -qx 'permitrootlogin no' "$config" || { log_error 'root 的 Match 条件覆盖了加固项'; restore_files; return 1; }
    fi
    if [[ "$disable_password" == yes ]]; then
        for key in passwordauthentication kbdinteractiveauthentication; do
            grep -qx "$key no" "$expected" || { log_error "最终 $key 不符合预期"; restore_files; return 1; }
        done
        if ! grep -qx 'authenticationmethods publickey' "$expected" || ! grep -qx 'pubkeyauthentication yes' "$expected"; then
            log_error 'Match/Include 阻止公钥认证配置生效'; restore_files; return 1
        fi
    fi
    if [[ -n "$SSH_SOCKET" && -n "$new_port" && -x "$SSH_SOCKET_GENERATOR" ]]; then
        log_info '检测到 sshd-socket-generator（Ubuntu），socket 监听将按 sshd_config 端口自动生成，不写 drop-in'
    elif [[ -n "$SSH_SOCKET" && -n "$new_port" ]]; then
        if ! mkdir -p "$(dirname "$SSH_SOCKET_FILE")" || ! backup_file "$SSH_SOCKET_FILE"; then restore_files; return 1; fi
        printf '[Socket]\nListenStream=\n' > "$config" || { restore_files; return 1; }
        # systemctl show 每个监听占一行（如 0.0.0.0:22 与 [::]:22）；read -a 只读首行会丢掉其余监听，必须用 -d ''。
        read -r -d '' -a socket_tokens <<< "$SSH_SOCKET_LISTENERS" || true
        if (( ${#socket_tokens[@]} < 2 || ${#socket_tokens[@]} % 2 != 0 )); then
            log_error "无法解析 socket 监听: $SSH_SOCKET_LISTENERS"; restore_files; return 1
        fi
        for (( attempt=0; attempt<${#socket_tokens[@]}; attempt+=2 )); do
            listener="${socket_tokens[$attempt]}"; type="${socket_tokens[$((attempt+1))]}"
            if [[ "$type" != '(Stream)' ]] || ! valid_port "${listener##*:}"; then
                log_error '不支持自动修改此 socket 监听格式'; restore_files; return 1
            fi
            printf 'ListenStream=%s\n' "$listener" >> "$config" || { restore_files; return 1; }
            if [[ "$listener" == *:* ]]; then listener="${listener%:*}:$new_port"; else listener="$new_port"; fi
            printf 'ListenStream=%s\n' "$listener" >> "$config" || { restore_files; return 1; }
        done
        # 重复配置不重复累积同一 ListenStream。
        if ! awk '!seen[$0]++' "$config" > "$main_clean" || ! cp -- "$main_clean" "$config"; then restore_files; return 1; fi
        atomic_write "$SSH_SOCKET_FILE" "$config" || { restore_files; return 1; }
    fi
    # 放行失败就回滚配置；绝不删旧规则。回滚保留新 allow 是刻意的安全选择。
    if [[ -n "$new_port" ]] && ufw_active; then
        ufw allow "$new_port/tcp" comment SSH || { restore_files; return 1; }
    fi
    if ! reload_ssh; then rollback_ssh; return 1; fi
    if [[ -n "$new_port" ]]; then
        actual=no
        for attempt in {1..10}; do if port_is_listening "$new_port"; then actual=yes; break; fi; sleep 1; done
        [[ "$actual" == yes ]] || { log_error '新端口未监听'; rollback_ssh; return 1; }
    fi
    if ! sync_fail2ban_ports; then log_error 'Fail2ban 同步失败，回滚 SSH'; rollback_ssh; return 1; fi
    log_info "SSH 已加载；备份: $BACKUP_DIR"
    if [[ -n "$SSH_SOCKET" ]]; then
        # socket 模式下 sshd -T 的 port 不代表实际入口。
        printf '%s 监听: %s\n' "$SSH_SOCKET" "$(systemctl show -p Listen --value "$SSH_SOCKET" | sed 's/ (Stream)//' | paste -sd' ' -)"
        ssh_effective | awk '$1 ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods)$/ {print}' || return 1
    else
        ssh_effective | awk '$1 ~ /^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods)$/ {print}' || return 1
    fi
    log_warn '旧端口与规则未自动删除。请先在第二个终端测试新入口，再人工清理旧监听/规则及云安全组。'
    [[ -z "$new_port" ]] || printf '测试命令: ssh -o IdentitiesOnly=yes -p %s 用户名@服务器\n' "$new_port"
}
wait_fail2ban() {
    local attempt
    for attempt in {1..10}; do
        if systemctl is-active --quiet fail2ban && fail2ban-client ping >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    log_error 'Fail2ban 服务或 sshd jail 未就绪'
    return 1
}
install_fail2ban() {
    local ports temp bantime=86400 findtime=600 maxretry=3 backend
    log_step '配置 Fail2ban'
    require_commands sshd ss || return 1
    command -v fail2ban-client >/dev/null 2>&1 || apt_install fail2ban || return 1
    ports=$(ssh_entry_ports | paste -sd, -) || return 1
    [[ -n "$ports" ]] || return 1
    backend=systemd
    if [[ -f /var/log/auth.log ]]; then backend=auto; else apt_install python3-systemd || return 1; fi
    if confirm '修改默认封禁参数（封禁86400秒/统计窗口600秒/失败3次）？'; then
        ask '封禁秒数: ' bantime || return 1
        valid_uint "$bantime" 1 2147483647 || { log_error '封禁秒数须为正整数'; return 1; }
        ask '统计窗口秒数: ' findtime || return 1
        valid_uint "$findtime" 1 2147483647 || { log_error '统计窗口须为正整数'; return 1; }
        ask '最大失败次数: ' maxretry || return 1
        valid_uint "$maxretry" 1 1000 || { log_error '最大失败次数须为 1–1000 的整数'; return 1; }
    fi
    start_change || return 1
    mkdir -p "$(dirname "$FAIL2BAN_CONFIG")" && backup_file "$FAIL2BAN_CONFIG" || return 1
    temp=$(mktemp "$BACKUP_DIR/fail2ban.XXXXXX") || return 1
    { printf '[sshd]\nenabled = true\nport = %s\nbackend = %s\nbantime = %s\nfindtime = %s\nmaxretry = %s\n' "$ports" "$backend" "$bantime" "$findtime" "$maxretry"
      [[ "$backend" != auto ]] || printf 'logpath = /var/log/auth.log\n'; } > "$temp" || return 1
    if ! atomic_write "$FAIL2BAN_CONFIG" "$temp" || ! fail2ban-client -t; then restore_files; return 1; fi
    if ! systemctl enable --now fail2ban || ! systemctl restart fail2ban || ! wait_fail2ban; then
        restore_files || log_error 'Fail2ban 配置回滚失败'
        systemctl restart fail2ban || log_warn '旧 Fail2ban 服务未能恢复，请检查 journal'
        return 1
    fi
    fail2ban-client status sshd
    # OpenSSH 9.8+ 由 sshd-session 记录认证日志，Fail2ban 1.1.0 之前的 sshd 过滤器不识别；jail 能加载不代表能匹配。
    if [[ -e /usr/lib/openssh/sshd-session ]] && ! grep -qs 'sshd-session' /etc/fail2ban/filter.d/sshd.conf; then
        log_warn '认证日志来自 sshd-session，但当前 Fail2ban sshd 过滤器未适配（需 1.1.0+），可能匹配不到失败登录'
    fi
    if [[ "$backend" == systemd ]]; then
        log_info '验证匹配：fail2ban-regex systemd-journal sshd（应能统计到失败登录）'
    else
        log_info '验证匹配：fail2ban-regex /var/log/auth.log sshd（应能统计到失败登录）'
    fi
}
configure_ssh_motd() {
    local temp action
    log_step 'SSH 欢迎信息（仅管理自己的脚本）'
    ask '1=启用/更新，2=禁用，0=返回: ' action || return 1
    [[ "$action" == 0 ]] && return 0
    [[ "$action" == 1 || "$action" == 2 ]] || { log_error '选择无效'; return 1; }
    start_change || return 1
    mkdir -p "$(dirname "$MOTD_FILE")" && backup_file "$MOTD_FILE" || return 1
    if [[ "$action" == 2 ]]; then
        [[ ! -f "$MOTD_FILE" ]] || chmod -x "$MOTD_FILE" || return 1
        return 0
    fi
    temp=$(mktemp "$BACKUP_DIR/motd.XXXXXX") || return 1
    cat > "$temp" <<'MOTD'
#!/bin/bash
printf '\n欢迎登录 %s\n' "$(hostname)"
printf '内核: %s  运行时间: %s\n' "$(uname -r)" "$(uptime -p)"
printf '负载: %s\n' "$(awk '{print $1, $2, $3}' /proc/loadavg)"
free -h | awk '/^Mem:/ {printf "内存: %s / %s\n", $3, $2}'
df -h / | awk 'NR==2 {printf "根分区: %s / %s (%s)\n", $3, $2, $5}'
printf '登录会话: %s\n' "$(who | wc -l)"
printf '更新状态以本机 APT 缓存为准；请定期运行 apt-get update。\n'
[[ ! -f /var/run/reboot-required ]] || printf '注意：系统提示需要重启。\n'
printf '\n'
MOTD
    bash -n "$temp" && atomic_write "$MOTD_FILE" "$temp" 0755 || return 1
    log_info '保留了发行版原有 MOTD。实际 SSH 展示取决于 PAM 动态 MOTD 配置。'
    "$MOTD_FILE"
}
write_alias_payload() {
    cat <<'ALIASES'
alias ll='ls -alh --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias egrep='grep -E --color=auto'
alias fgrep='grep -F --color=auto'
alias df='df -h'
alias free='free -h'
alias du='du -h'
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias mkdir='mkdir -pv'
alias wget='wget -c'
alias path='printf "%s\n" "${PATH//:/$'"'"'\n'"'"'}"'
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias ports='ss -tulnp'
ALIASES
}
write_vim_payload() {
    local scope="${1:-}"
    # 全局 vimrc.local 先于 defaults.vim 加载；无 ~/.vimrc 的用户随后会被 defaults.vim 设为 mouse=a。
    # 因此在此主动加载 defaults.vim 并阻止其再次加载，使下方设置成为最终值。
    if [[ "$scope" == global ]]; then
        cat <<'VIM'
if !exists('g:skip_defaults_vim') && filereadable(expand('$VIMRUNTIME/defaults.vim'))
    source $VIMRUNTIME/defaults.vim
endif
let g:skip_defaults_vim = 1
VIM
    fi
    cat <<'VIM'
set nocompatible
syntax on
set encoding=utf-8
set fileencodings=ucs-bom,utf-8,gb18030,latin1
set backspace=indent,eol,start
set autoindent
set tabstop=4 shiftwidth=4 softtabstop=4 expandtab
set hlsearch incsearch ignorecase smartcase
set ruler showcmd laststatus=2 wildmenu
set pastetoggle=<F2>
" SSH 默认使用终端自己的鼠标选择，不强制访问远端系统剪贴板。
set mouse=
set selectmode=
set selection=inclusive
if exists('+clipboard')
    set clipboard=
endif
filetype plugin indent on
" 保留写入安全和崩溃恢复；敏感文件另行配置。
set swapfile writebackup nobackup
set history=1000 undolevels=1000
set noerrorbells novisualbell
VIM
}
# 用户 ~/.bashrc 晚于 /etc/bash.bashrc 加载，其中同名 alias（如 Ubuntu 默认的 ll/la/l）会覆盖全局值。
# 只读检查并列出，不改用户文件；需要统一时改用“指定用户”范围。
# 与全局值完全相同的定义（如 Debian 默认的 alias ls='ls --color=auto'）不算覆盖。
report_alias_overrides() {
    local name uid home names found=0
    while IFS=: read -r name _ uid _ _ home _; do
        [[ ( "$uid" == 0 || "$uid" -ge 1000 ) && "$uid" != 65534 && -f "$home/.bashrc" && ! -L "$home/.bashrc" ]] || continue
        names=$(awk -v b="$ALIASES_BEGIN" -v e="$ALIASES_END" '
            FNR == NR { if (match($0, /^alias [^=]+=/)) want[substr($0, 7, RLENGTH - 7)] = $0; next }
            $0 == b {inside=1; next} $0 == e {inside=0; next}
            inside {next}
            {
                line = $0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)
                if (line !~ /^alias[[:space:]]+[^=[:space:]]+=/) next
                sub(/^alias[[:space:]]+/, "alias ", line)
                name = substr(line, 7); sub(/=.*/, "", name)
                if ((name in want) && line != want[name] && !(name in shown)) { shown[name] = 1; printf "%s ", name }
            }
        ' <(write_alias_payload) "$home/.bashrc")
        if [[ -n "$names" ]]; then log_warn "用户 $name 的 ~/.bashrc 会覆盖全局别名: ${names% }"; found=1; fi
    done < <(getent passwd)
    (( found == 0 )) || log_info '如需对这些用户生效，请选择范围 2（指定用户）写入其 ~/.bashrc'
}
print_environment_refresh() {
    local scope="$1"
    if [[ "$AUTO_REFRESH" == yes ]]; then log_info '退出菜单后将自动刷新当前终端的别名/EDITOR'; return 0; fi
    log_warn '别名/EDITOR 已写入配置；子进程不能修改当前父终端。请在需要刷新的原 Bash 终端执行：'
    printf '  unalias %s 2>/dev/null || true; source /etc/bash.bashrc; source ~/.bashrc\n' "$MANAGED_ALIAS_NAMES"
    if [[ "$scope" != 1 ]]; then log_info '请以被配置的目标用户执行上述命令，不要在 sudo 子进程中 source 用户配置。'; fi
    log_info '也可在原 Bash 中执行：source /路径/init-new-system.sh --refresh-env'
    log_info '下次可用 source /路径/init-new-system.sh --run 启动，退出后自动刷新'
}
configure_user_environment() {
    local scope user_input username home bashrc vimrc owner action edit_vim edit_editor temp vim_path
    local users=() bashrcs=() vimrcs=() owners=()
    log_step '用户环境（别名、编辑器、Vim 分别独立处理）'
    ask '范围：1=全局，2=指定用户 [1]: ' scope || return 1
    scope="${scope:-1}"
    case "$scope" in
        1) bashrcs+=("$GLOBAL_BASHRC"); vimrcs+=("$GLOBAL_VIMRC"); owners+=('') ;;
        2)
            ask '用户名（空格分隔）: ' user_input || return 1
            read -r -a users <<< "$user_input"
            (( ${#users[@]} )) || { log_error '未输入用户名'; return 1; }
            for username in "${users[@]}"; do
                validate_user "$username" || return 1
                home=$(user_home "$username") || return 1
                [[ "$home" == /* && -d "$home" && ! -L "$home" ]] || { log_error "用户 $username 的 home 不存在或为链接"; return 1; }
                bashrcs+=("$home/.bashrc"); vimrcs+=("$home/.vimrc"); owners+=("$username")
            done ;;
        *) log_error '范围无效'; return 1 ;;
    esac
    ask '别名：1=启用/更新，2=禁用，3=查看，0=跳过 [1]: ' action || return 1
    action="${action:-1}"
    [[ "$action" =~ ^[0123]$ ]] || { log_error '选择无效'; return 1; }
    edit_editor=no; edit_vim=no
    if confirm '设置默认编辑器为 Vim？' y; then edit_editor=yes; fi
    if confirm '配置 SSH 友好的 Vim 默认设置？' y; then edit_vim=yes; fi
    if [[ "$edit_editor" == yes || "$edit_vim" == yes ]]; then
        command -v vim >/dev/null 2>&1 || apt_install vim || return 1
    fi
    start_change || return 1
    temp=$(mktemp "$BACKUP_DIR/environment.XXXXXX") || return 1
    for username in "${!bashrcs[@]}"; do
        bashrc="${bashrcs[$username]}"; vimrc="${vimrcs[$username]}"; owner="${owners[$username]}"
        case "$action" in
            1) write_alias_payload > "$temp" || { restore_files; return 1; }; update_block "$bashrc" "$ALIASES_BEGIN" "$ALIASES_END" "$temp" "$owner" || { restore_files; return 1; } ;;
            2) write_alias_payload | sed 's/^alias /#alias /' > "$temp" || { restore_files; return 1; }; update_block "$bashrc" "$ALIASES_BEGIN" "$ALIASES_END" "$temp" "$owner" || { restore_files; return 1; } ;;
            3)
                if [[ -f "$bashrc" ]]; then
                    printf '\n%s\n' "$bashrc"
                    awk -v b="$ALIASES_BEGIN" -v e="$ALIASES_END" '$0==b {show=1} show {print} $0==e {show=0}' "$bashrc"
                    if grep -q '^# Custom aliases - debian12-setup$' "$bashrc"; then
                        awk '/^# Custom aliases - debian12-setup$/ {show=1} show {print} show && /^#?alias ports=/ {show=0}' "$bashrc"
                    fi
                fi ;;
        esac
        if [[ "$edit_editor" == yes ]]; then
            printf 'export EDITOR=vim\nexport VISUAL=vim\n' > "$temp" || { restore_files; return 1; }
            update_block "$bashrc" "$EDITOR_BEGIN" "$EDITOR_END" "$temp" "$owner" || { restore_files; return 1; }
        fi
        if [[ "$edit_vim" == yes ]]; then
            [[ "$scope" != 1 ]] || mkdir -p "$(dirname "$vimrc")" || return 1
            # 旧配置及用户附加内容保留；后面的专属区块覆盖不安全默认项。
            if [[ "$scope" == 1 ]]; then write_vim_payload global > "$temp"; else write_vim_payload > "$temp"; fi || { restore_files; return 1; }
            update_block "$vimrc" "$VIM_BEGIN" "$VIM_END" "$temp" "$owner" || { restore_files; return 1; }
        fi
        [[ ! -f "$bashrc" ]] || bash -n "$bashrc" || { restore_files; return 1; }
    done
    if [[ "$scope" == 1 && "$edit_editor" == yes ]]; then
        # 实际可能是 vim.basic/vim.nox/vim.gtk3 等，不能写死 vim.basic。EDITOR 已写入，此处失败只告警。
        vim_path=$(readlink -f "$(command -v vim)")
        if [[ -n "$vim_path" ]] && update-alternatives --list editor 2>/dev/null | grep -qxF "$vim_path"; then
            update-alternatives --set editor "$vim_path" || log_warn '无法设置全局 editor alternatives'
        else
            log_warn "editor alternatives 中没有 ${vim_path:-vim}，保留现有设置"
        fi
    fi
    if [[ "$scope" == 1 && "$action" == 1 ]]; then report_alias_overrides; fi
    if [[ "$action" == 1 || "$action" == 2 || "$edit_editor" == yes ]]; then
        print_environment_refresh "$scope"
        ENV_REFRESH_SCOPE="$scope"
    fi
    log_info "环境配置完成，备份: ${BACKUP_DIR}；Vim 重开后加载。"
}
run_all() {
    local step
    confirm '执行全部操作？每个敏感步骤仍将单独确认。' || return 0
    # 先确认 SSH 最终端口，再创建 Fail2ban jail，避免封禁错端口。
    for step in "${MENU_STEPS[@]}"; do
        "$step" || { trap - HUP INT TERM; log_error "步骤 $step 失败，停止全部操作；不会继续加固或自动重启"; return 1; }
        trap - HUP INT TERM
    done
    log_info '全部步骤完成。请验证新会话、sudo、容器网络和防火墙，再安排重启。'
}
# 菜单状态标记：✓ 已就绪，! 需要注意，○ 未配置；纯文本为当前值。
status_ok() { printf '%s✓ %s%s' "$C_GREEN" "$1" "$C_RESET"; }
status_warn() { printf '%s! %s%s' "$C_YELLOW" "$1" "$C_RESET"; }
status_off() { printf '%s○ %s%s' "$C_DIM" "$1" "$C_RESET"; }
# 按终端显示宽度补齐（中文占两列）；C.UTF-8 保证 ${#s} 按字符而非字节计数。
pad_label() {
    local LC_ALL=C.UTF-8 s="$1" ascii
    ascii="${s//[^[:ascii:]]/}"
    printf '%s%*s' "$s" $(( $2 - ${#ascii} - 2 * (${#s} - ${#ascii}) )) ''
}
normal_users() { getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1}'; }
menu_status() {
    local missing=0 cmd names ports banned username home total
    case "$1" in
        update_system) [[ ! -f /var/run/reboot-required ]] || status_warn '待重启' ;;
        configure_swap)
            total=$(awk 'NR > 1 {s += $3} END {printf "%d", s / 1024}' /proc/swaps 2>/dev/null)
            if [[ "${total:-0}" == 0 ]]; then status_off '未启用'; else status_ok "$(fmt_mib "$total")"; fi ;;
        install_common_tools)
            for cmd in vim git curl htop tmux tree; do command -v "$cmd" >/dev/null 2>&1 || missing=$((missing + 1)); done
            if (( missing == 0 )); then status_ok '已安装'; else status_off "缺 ${missing} 项"; fi ;;
        configure_timezone) current_timezone ;;
        install_docker)
            if ! command -v docker >/dev/null 2>&1; then status_off '未安装'
            elif systemctl is-active --quiet docker; then status_ok '运行中'
            else status_warn '未运行'; fi ;;
        create_user)
            names=$(normal_users | paste -sd, - | sed 's/,/, /g')
            if [[ -n "$names" ]]; then printf '%s' "$names"; else status_off '无普通用户'; fi ;;
        add_ssh_key)
            names=$( { printf 'root\n'; normal_users; } | while read -r username; do
                home=$(user_home "$username")
                [[ ! -s "$home/.ssh/authorized_keys" ]] || printf '%s\n' "$username"
            done | paste -sd, - | sed 's/,/, /g')
            if [[ -n "$names" ]]; then status_ok "$names"; else status_off '无公钥'; fi ;;
        configure_user_environment)
            if awk -v b="$ALIASES_BEGIN" -v e="$ALIASES_END" '$0==b {i=1} $0==e {i=0} i && /^alias / {f=1} END {exit !f}' "$GLOBAL_BASHRC" 2>/dev/null; then
                status_ok '全局别名'
            else
                status_off '未配置'
            fi ;;
        configure_ssh_motd)
            if [[ -x "$MOTD_FILE" ]]; then status_ok '已启用'; else status_off '未启用'; fi ;;
        configure_ssh)
            ports=$(ssh_entry_ports 2>/dev/null | paste -sd, -)
            if [[ -f "$SSH_MANAGED" ]] && grep -qxF "$SSH_BEGIN" "$SSH_CONFIG" 2>/dev/null; then
                status_ok "已加固 · 端口 ${ports:-?}"
            else
                status_off "未加固 · 端口 ${ports:-?}"
            fi ;;
        configure_ufw)
            if ! command -v ufw >/dev/null 2>&1; then status_off '未安装'
            elif ufw_active; then status_ok '已启用'
            else status_warn '未启用'; fi ;;
        install_fail2ban)
            if ! command -v fail2ban-client >/dev/null 2>&1; then status_off '未安装'
            elif systemctl is-active --quiet fail2ban; then
                banned=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/ {gsub(/[[:space:]]/, "", $2); print $2}')
                status_ok "运行中${banned:+ · 封禁 ${banned}}"
            else
                status_warn '未运行'
            fi ;;
    esac
}
# 编号即 run_all 的推荐执行顺序；修改时与 MENU_STEPS、run_all 保持一致。
MENU_STEPS=(update_system install_common_tools configure_timezone configure_swap install_docker create_user add_ssh_key configure_user_environment configure_ssh_motd configure_ssh configure_ufw install_fail2ban)
MENU_LABELS=('更新系统' '常用工具' '时区' '虚拟内存 (swap)' 'Docker' '创建用户' 'SSH 公钥' '别名 / 编辑器 / Vim' 'SSH 欢迎信息' 'SSH 加固 / 端口' 'UFW 防火墙' 'Fail2ban')
show_menu() {
    local i os rule
    os=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-$ID}")
    rule=$(printf '%.0s─' {1..52})
    printf '\n  %sDebian/Ubuntu 初始化%s\n' "$C_BOLD" "$C_RESET"
    printf '  %s%s · %s · 内核 %s%s\n' "$C_DIM" "$(hostname)" "$os" "$(uname -r)" "$C_RESET"
    printf '  %s%s%s\n' "$C_DIM" "$rule" "$C_RESET"
    for i in "${!MENU_STEPS[@]}"; do
        case "$i" in
            0) printf '\n  %s系统%s\n' "$C_CYAN" "$C_RESET" ;;
            5) printf '\n  %s用户%s\n' "$C_CYAN" "$C_RESET" ;;
            9) printf '\n  %s安全%s\n' "$C_CYAN" "$C_RESET" ;;
        esac
        printf '   %s%2d%s  %s  %s\n' "$C_BOLD" $((i + 1)) "$C_RESET" "$(pad_label "${MENU_LABELS[$i]}" 20)" "$(menu_status "${MENU_STEPS[$i]}")"
    done
    printf '\n  %s%s%s\n' "$C_DIM" "$rule" "$C_RESET"
    printf '   %s a%s  按顺序执行全部       %s 0%s  退出\n' "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET"
}
exit_menu() { [[ -z "$ENV_REFRESH_SCOPE" ]] || print_environment_refresh "$ENV_REFRESH_SCOPE"; }
main() {
    local choice step
    case "${1:-}" in
        --help|-h) printf '%s\n' 'sudo bash init-new-system.sh' '运行并在退出后自动刷新当前终端：source init-new-system.sh --run' '仅刷新当前终端：source init-new-system.sh --refresh-env'; return 0 ;;
        --auto-refresh) AUTO_REFRESH=yes ;;
        --refresh-env|--run) log_error "必须在原 Bash 中 source 本脚本 $1，不能作为子进程执行"; return 1 ;;
        '') ;;
        *) log_error '未知参数'; return 1 ;;
    esac
    check_system || return 1
    [[ -t 0 ]] || { log_error '需要交互终端，请保存脚本后 sudo bash 执行，不能 curl | bash'; return 1; }
    acquire_lock || return 1
    detect_ssh_connection
    while true; do
        show_menu
        ask "$(printf '\n  %s选择 [1-%d/a/0]:%s ' "$C_BOLD" "${#MENU_STEPS[@]}" "$C_RESET")" choice || { exit_menu; return 0; }
        case "$choice" in
            a|A) step=run_all ;;
            0) exit_menu; return 0 ;;
            *)
                if [[ "$choice" =~ ^[0-9]{1,2}$ ]] && (( 10#$choice >= 1 && 10#$choice <= ${#MENU_STEPS[@]} )); then
                    step="${MENU_STEPS[10#$choice - 1]}"
                else
                    log_warn '选择无效'; continue
                fi ;;
        esac
        if ! "$step"; then log_error "操作 $step 失败。请检查以上错误及备份；已返回菜单，不会自动继续。"; fi
        trap - HUP INT TERM
    done
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    main "$@"
fi