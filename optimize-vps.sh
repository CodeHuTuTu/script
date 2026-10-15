#!/bin/bash
# Debian/Ubuntu VPS 保守调优：只管理明确选择的 TCP 参数及专属配置。
# 不修改 OOM/panic、IP 转发、rp_filter、内存水位及全局 sysctl.conf。

GLOBAL_SYSCTL_FILE=/etc/sysctl.conf
GLOBAL_LIMITS_FILE=/etc/security/limits.conf
SERVICE_DROPIN_ROOT=/etc/systemd/system
SYSCTL_FILE=/etc/sysctl.d/90-properties-script-vps.conf
LIMITS_FILE=/etc/security/limits.d/90-properties-script-vps.conf
BACKUP_ROOT=/var/backups/properties-script-vps
PROC_SYS=/proc/sys
ROLLED_BACK_MARK=rolled-back
# 与 init-new-system.sh 共用同一把锁；放在仅 root 可写的 /run。
LOCK_FILE=/run/properties-script.lock
BACKUP_DIR=
SYSCTL_KEYS=()
SYSCTL_VALUES=()
SERVICE_NAMES=()
CONGESTION_CONTROL=bbr
QDISC=fq
TUNE_BUFFERS=no
PAM_LIMITS=no
TOTAL_MEM=
NOFILE=
RMEM_MAX=
WMEM_MAX=
SOMAXCONN=
MAX_SYN_BACKLOG=
# 硬件/网络检测结果；缓冲区按 2×BDP 计算，并以内存档位为上限。
BUFFER_CAP=
CPU_CORES=
VIRT_TYPE=
NET_IFACE=
NET_SPEED=
NET_TX_QUEUES=
RTT_SAMPLES=0
RTT_MEDIAN=
RETRANS_PCT=
BANDWIDTH_MBPS=
CLIENT_RTT_MS=
BDP_BYTES=
RECOMMENDED_CC=cubic

log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
log_title() { printf '\n=== %s ===\n' "$*"; }
ask() { IFS= read -r -p "$1" "$2" || { log_warn '输入结束，取消操作'; return 1; }; }
confirm() {
    local answer prompt="$1" default="${2:-n}"
    [[ "$default" == y ]] && prompt+=' [Y/n]: ' || prompt+=' [y/N]: '
    ask "$prompt" answer || return 1
    answer="${answer:-$default}"
    [[ "${answer,,}" == y || "${answer,,}" == yes ]]
}
acquire_lock() {
    command -v flock >/dev/null 2>&1 || { log_warn '缺少 flock，无法阻止多个实例并发修改'; return 0; }
    exec 9> "$LOCK_FILE" || return 1
    flock -n 9 || { log_error '另一个 properties-script 脚本正在运行，请等待其结束'; return 1; }
}
require_commands() {
    local item
    for item in "$@"; do command -v "$item" >/dev/null 2>&1 || { log_error "缺少命令: $item"; return 1; }; done
}
valid_uint() { [[ "$1" =~ ^[0-9]{1,10}$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }
mib() { printf '%dMiB' $(( $1 / 1048576 )); }
# ---- 发行版检测（与 init-new-system.sh 保持一致）----
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
    require_commands sysctl awk sort mktemp install stat cp mv
}
# 回滚只要求 root 和 Debian/Ubuntu，不做版本拦截：系统升级后也必须能撤销旧变更。
check_rollback_system() {
    check_root && read_os_release || return 1
    [[ "$OS_ID" == debian || "$OS_ID" == ubuntu ]] || { log_error '仅支持 Debian/Ubuntu'; return 1; }
    require_commands sysctl awk mktemp stat cp
}
check_legacy_config() {
    if [[ -f "$GLOBAL_SYSCTL_FILE" ]] && grep -qx '# VPS 优化配置' "$GLOBAL_SYSCTL_FILE"; then
        log_error '检测到旧版脚本整份生成的 sysctl.conf，其中可能包含 panic/关闭转发等设置。'
        log_error '请先评估并恢复旧备份的配置与运行值；本脚本不会假装已消除旧参数，也不会擅自覆盖。'
        return 1
    fi
    if [[ -f "$GLOBAL_LIMITS_FILE" ]] && grep -q '^# VPS-OPTIMIZE$' "$GLOBAL_LIMITS_FILE"; then
        log_warn '旧版 limits.conf 区块仍存在，请核对新旧限制；本脚本不自动删除。'
    fi
    return 0
}
detect_system() {
    TOTAL_MEM=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo) || return 1
    valid_uint "$TOTAL_MEM" 1 2147483647 || { log_error '无法读取有效的物理内存容量'; return 1; }
    # /proc/meminfo 不是容器内存上限。禁止在 namespace 中假设 root 有宿主权限。
    if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container --quiet; then
        log_error '检测到容器；请在宿主机管理内核参数及容器 ulimits'; return 1
    fi
    CPU_CORES=$(nproc 2>/dev/null)
    valid_uint "$CPU_CORES" 1 1000000 || CPU_CORES=1
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || true)
    detect_interface
    detect_network_conditions
}
# 默认路由所在网卡；名称会拼进 /sys 路径，先校验。
detect_interface() {
    local name
    command -v ip >/dev/null 2>&1 || { log_warn '缺少 ip 命令（iproute2），跳过网卡检测'; return 0; }
    name=$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
    [[ -n "$name" ]] || name=$(ip -6 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
    [[ "$name" =~ ^[A-Za-z0-9_.:-]{1,15}$ && "$name" != *..* && -d "/sys/class/net/$name" ]] || return 0
    NET_IFACE="$name"
    # virtio 等虚拟网卡常报告 -1 或读取报错；未知时由用户填写带宽。
    { read -r NET_SPEED < "/sys/class/net/$name/speed"; } 2>/dev/null || NET_SPEED=
    valid_uint "$NET_SPEED" 1 4000000 || NET_SPEED=
    NET_TX_QUEUES=$(find "/sys/class/net/$name/queues" -maxdepth 1 -name 'tx-*' 2>/dev/null | wc -l)
}
# 被动采样：读取现有 TCP 连接的 RTT 和开机以来的重传率，不主动向外发包。
detect_network_conditions() {
    local sample=''
    if command -v ss >/dev/null 2>&1; then
        sample=$(ss -tinH state established 2>/dev/null | awk '
            /^[^[:space:]]/ { skip = ($4 ~ /^(127\.|\[::1\]|\[::ffff:127\.)/); next }
            !skip && match($0, /rtt:[0-9.]+/) { print substr($0, RSTART + 4, RLENGTH - 4) }
        ' | sort -n | awk '{v[NR] = $1} END {if (NR) printf "%d %d\n", NR, v[int((NR + 1) / 2)] + 0.5}')
    fi
    read -r RTT_SAMPLES RTT_MEDIAN <<< "$sample"
    RTT_SAMPLES=${RTT_SAMPLES:-0}
    RETRANS_PCT=$(awk '$1 == "Tcp:" {
            if (!h) {for (i = 2; i <= NF; i++) col[$i] = i; h = 1; next}
            out = $col["OutSegs"]; re = $col["RetransSegs"]
        } END {if (out >= 10000) printf "%.2f", re * 100 / out}' /proc/net/snmp 2>/dev/null)
}
show_detection() {
    local speed='未知' retrans='发送量不足，无法估计'
    [[ -z "$NET_SPEED" ]] || speed="${NET_SPEED}Mbps"
    [[ -z "$RETRANS_PCT" ]] || retrans="${RETRANS_PCT}%"
    log_title '硬件与网络检测'
    printf '内核: %s  内存: %sMB  CPU: %s 核  虚拟化: %s\n' "$(uname -r)" "$TOTAL_MEM" "$CPU_CORES" "${VIRT_TYPE:-未知}"
    printf '默认网卡: %s  标称速率: %s  发送队列: %s\n' "${NET_IFACE:-未知}" "$speed" "${NET_TX_QUEUES:-未知}"
    if (( RTT_SAMPLES > 0 )); then
        printf '现有连接 RTT 中位数: %s（%s 个样本，可能含本次 SSH 会话）\n' "$( (( RTT_MEDIAN >= 1 )) && echo "${RTT_MEDIAN}ms" || echo '<1ms')" "$RTT_SAMPLES"
    else
        printf '现有连接 RTT: 无非回环样本\n'
    fi
    printf '开机以来 TCP 重传率: %s\n' "$retrans"
}
calculate_params() {
    valid_uint "$TOTAL_MEM" 1 2147483647 || { log_error '内存值必须是正整数'; return 1; }
    # 内存档位决定 nofile 与单连接缓冲区的上限（BUFFER_CAP）；实际目标由 BDP 决定。
    if (( 10#$TOTAL_MEM < 512 )); then NOFILE=16384; BUFFER_CAP=8388608
    elif (( 10#$TOTAL_MEM < 1024 )); then NOFILE=32768; BUFFER_CAP=12582912
    elif (( 10#$TOTAL_MEM < 2048 )); then NOFILE=51200; BUFFER_CAP=16777216
    elif (( 10#$TOTAL_MEM < 4096 )); then NOFILE=65536; BUFFER_CAP=33554432
    else NOFILE=100000; BUFFER_CAP=67108864
    fi
    RMEM_MAX=$BUFFER_CAP; WMEM_MAX=$BUFFER_CAP
    SOMAXCONN=4096; MAX_SYN_BACKLOG=8192
}
# 带宽×时延积：单连接要跑满链路，窗口至少为 BDP；内核会把部分缓冲用于元数据开销，因此目标取 2×BDP。
plan_buffers() {
    local target throughput
    BDP_BYTES=$(( BANDWIDTH_MBPS * CLIENT_RTT_MS * 125 ))
    target=$(( (BDP_BYTES * 2 + 1048575) / 1048576 * 1048576 ))
    (( target >= 4194304 )) || target=4194304
    if (( target > BUFFER_CAP )); then
        throughput=$(( BUFFER_CAP * 4 / (CLIENT_RTT_MS * 1000) ))
        log_warn "2×BDP 需要 $(mib "$target")，超过 ${TOTAL_MEM}MB 内存档位上限 $(mib "$BUFFER_CAP")；单连接在 ${CLIENT_RTT_MS}ms 下约可达 ${throughput}Mbps"
        target=$BUFFER_CAP
    fi
    RMEM_MAX=$target; WMEM_MAX=$target
}
pct_below() { awk -v r="$1" -v t="$2" 'BEGIN {exit !(r != "" && r + 0 < t + 0)}'; }
# 主线内核提供 bbr（v1）；不可用（模块缺失或被禁用）时推荐保持 cubic。
# 此处只做 modprobe -n 预检，不加载模块；实际加载在用户确认之后。
recommend_congestion() {
    [[ -r "$PROC_SYS/net/ipv4/tcp_available_congestion_control" ]] || { log_error '没有 TCP 算法注册列表'; return 1; }
    if cc_available bbr || { command -v modprobe >/dev/null 2>&1 && modprobe -n -q tcp_bbr 2>/dev/null; }; then
        RECOMMENDED_CC=bbr
    else
        RECOMMENDED_CC=cubic
        log_warn "内核 $(uname -r) 未提供 bbr，推荐保持 cubic"
    fi
    if (( CLIENT_RTT_MS <= 2 )) && { [[ -z "$RETRANS_PCT" ]] || pct_below "$RETRANS_PCT" 0.1; }; then
        log_info '低时延（局域网/同机房），BBR 与 cubic 差异很小'
    elif (( CLIENT_RTT_MS >= 100 )); then
        log_info '高时延链路：BBR 配合足够的缓冲区收益最明显'
    fi
    if [[ -n "$RETRANS_PCT" ]] && ! pct_below "$RETRANS_PCT" 1; then
        log_info "重传率 ${RETRANS_PCT}% 偏高：BBR 不把丢包直接当拥塞信号，通常能维持更高吞吐，但可能挤占同链路的其他流量"
    fi
}
ask_user_params() {
    local choice names default_bw default_rtt default_cc default_qdisc current_max
    show_detection
    log_title '网络条件（回车采用方括号内的值）'
    default_bw=${NET_SPEED:-1000}
    (( default_bw <= 10000 )) || default_bw=10000
    [[ -z "$NET_SPEED" ]] || log_info '网卡标称速率常高于 VPS 实际限速，请按套餐带宽填写'
    ask "出口带宽 Mbps [${default_bw}]: " BANDWIDTH_MBPS || return 1
    BANDWIDTH_MBPS=${BANDWIDTH_MBPS:-$default_bw}
    valid_uint "$BANDWIDTH_MBPS" 1 400000 || { log_error '带宽须为 1–400000 的整数'; return 1; }
    BANDWIDTH_MBPS=$((10#$BANDWIDTH_MBPS))
    default_rtt=100
    # 样本足够时以实测中位数为默认值；亚毫秒（局域网）按 1ms 计。
    if (( RTT_SAMPLES >= 3 )); then default_rtt=$(( RTT_MEDIAN >= 1 ? RTT_MEDIAN : 1 )); fi
    ask "主要客户端的典型 RTT ms（跨地域常见 50–200）[${default_rtt}]: " CLIENT_RTT_MS || return 1
    CLIENT_RTT_MS=${CLIENT_RTT_MS:-$default_rtt}
    valid_uint "$CLIENT_RTT_MS" 1 2000 || { log_error 'RTT 须为 1–2000 的整数'; return 1; }
    CLIENT_RTT_MS=$((10#$CLIENT_RTT_MS))
    recommend_congestion || return 1
    plan_buffers
    log_title '推荐'
    printf 'BDP: %s（%sMbps × %sms）  缓冲区上限: %s\n' "$(mib $(( BDP_BYTES + 1048575 )))" "$BANDWIDTH_MBPS" "$CLIENT_RTT_MS" "$(mib "$RMEM_MAX")"
    printf '拥塞控制: %s  默认 qdisc: %s\n' "$RECOMMENDED_CC" "$([[ "$RECOMMENDED_CC" == bbr ]] && echo fq || echo fq_codel)"
    [[ "$RECOMMENDED_CC" == bbr ]] && default_cc=1 || default_cc=3
    ask "拥塞控制：1=bbr，2=bbr2（需对应内核），3=cubic [${default_cc}]: " choice || return 1
    case "${choice:-$default_cc}" in 1) CONGESTION_CONTROL=bbr ;; 2) CONGESTION_CONTROL=bbr2 ;; 3) CONGESTION_CONTROL=cubic ;; *) log_error '拥塞控制选择无效'; return 1 ;; esac
    # BBR 依赖 pacing：fq 提供高效 pacing（4.13+ 内核无 fq 时 BBR 也会内部 pacing）；cubic 搭配 fq_codel 抑制排队时延。
    [[ "$CONGESTION_CONTROL" == cubic ]] && default_qdisc=2 || default_qdisc=1
    ask "默认 qdisc：1=fq，2=fq_codel，3=fq_pie，4=cake [${default_qdisc}]: " choice || return 1
    case "${choice:-$default_qdisc}" in 1) QDISC=fq ;; 2) QDISC=fq_codel ;; 3) QDISC=fq_pie ;; 4) QDISC=cake ;; *) log_error 'qdisc 选择无效'; return 1 ;; esac
    [[ "$QDISC" != cake ]] || log_warn 'CAKE 没有设置带宽整形，不能承诺改善上游瓶颈；不会替换现有接口队列。'
    ask '用途：1=TCP服务，2=Web，3=通用 [3]: ' choice || return 1
    case "${choice:-3}" in 1|3) ;; 2) SOMAXCONN=8192; MAX_SYN_BACKLOG=16384 ;; *) log_error '用途选择无效'; return 1 ;; esac
    current_max=$(sysctl -n net.ipv4.tcp_rmem | awk '{print $3}')
    if valid_uint "$current_max" 1 2147483647 && (( RMEM_MAX > 10#$current_max )); then
        if confirm "将 TCP 缓冲区上限由 $(mib "$current_max") 提高到 $(mib "$RMEM_MAX")？" y; then TUNE_BUFFERS=yes; fi
    elif [[ -f "$SYSCTL_FILE" ]] && grep -q '^[[:space:]]*net\.ipv4\.tcp_rmem[[:space:]]*=' "$SYSCTL_FILE"; then
        # 当前值来自本脚本上次的配置：不纳入计划会从专属文件中删除，重启后悄悄回到默认值。
        TUNE_BUFFERS=yes
        log_info "当前缓冲区上限 $(mib "$current_max") 来自本脚本既有配置，保持不变并继续持久化（只增不减）"
    else
        log_info "当前缓冲区上限 $(mib "${current_max:-0}") 已满足目标，不调整（只增不减）"
    fi
    if confirm "将 PAM 新登录会话的 nofile soft/hard 至少设置为 ${NOFILE}？不影响已运行服务"; then PAM_LIMITS=yes; fi
    ask '需要设置 nofile 的 systemd 服务（完整 .service 名，空格分隔；空白跳过）: ' names || return 1
    read -r -a SERVICE_NAMES <<< "$names"
    validate_services || return 1
    log_info "目标: $CONGESTION_CONTROL / ${QDISC}；不会自动重启服务或修改活跃网卡队列。"
}
# 在确认前校验，避免进入写入阶段后才失败并整体回滚。
validate_services() {
    local service
    (( ${#SERVICE_NAMES[@]} )) || return 0
    require_commands systemctl || return 1
    for service in "${SERVICE_NAMES[@]}"; do
        [[ "$service" =~ ^[a-zA-Z0-9_:@.-]+\.service$ && "$service" != *..* ]] || { log_error "非法服务名: $service"; return 1; }
        [[ "$(systemctl show -p LoadState --value "$service")" == loaded ]] || { log_error "服务不存在: $service"; return 1; }
    done
}
cc_available() { awk -v cc="$1" '{for(i=1;i<=NF;i++) if($i==cc) found=1} END {exit !found}' "$PROC_SYS/net/ipv4/tcp_available_congestion_control"; }
check_kernel_support() {
    [[ -r "$PROC_SYS/net/ipv4/tcp_available_congestion_control" ]] || { log_error '没有 TCP 算法注册列表'; return 1; }
    if ! cc_available "$CONGESTION_CONTROL"; then
        if command -v modprobe >/dev/null 2>&1; then modprobe "tcp_$CONGESTION_CONTROL" 2>/dev/null || true; fi
    fi
    # 主线内核没有 bbr2；所选 bbr2 不可用时先退回同族的 bbr，再退回 cubic。计划会在确认前显示。
    if ! cc_available "$CONGESTION_CONTROL" && [[ "$CONGESTION_CONTROL" == bbr2 ]]; then
        if command -v modprobe >/dev/null 2>&1; then modprobe tcp_bbr 2>/dev/null || true; fi
        if cc_available bbr; then log_warn 'bbr2 不可用，改为 bbr'; CONGESTION_CONTROL=bbr; fi
    fi
    if ! cc_available "$CONGESTION_CONTROL"; then
        if cc_available cubic; then log_warn "$CONGESTION_CONTROL 不可用，改为 cubic"; CONGESTION_CONTROL=cubic
        else log_error '所选算法及 cubic 均不可用'; return 1
        fi
    fi
    # 模块可能内建；modprobe 失败不直接等于不支持，最终由 sysctl 写入校验。
    if command -v modprobe >/dev/null 2>&1; then modprobe "sch_$QDISC" 2>/dev/null || true; fi
}
add_sysctl() {
    local key="$1" value="$2" current slash=/
    current=$(sysctl -n "$key") || { log_error "目标内核不支持 $key"; return 1; }
    [[ -r "$PROC_SYS/${key//./$slash}" && -w "$PROC_SYS/${key//./$slash}" ]] || { log_error "没有 $key 的写入权限"; return 1; }
    [[ -n "$current" ]] || return 1
    SYSCTL_KEYS+=("$key"); SYSCTL_VALUES+=("$value")
}
add_at_least() {
    local key="$1" desired="$2" current
    current=$(sysctl -n "$key") || return 1
    valid_uint "$current" 0 2147483647 && valid_uint "$desired" 1 2147483647 || return 1
    (( 10#$current > 10#$desired )) && desired="$current"
    add_sysctl "$key" "$desired"
}
build_sysctl_plan() {
    SYSCTL_KEYS=(); SYSCTL_VALUES=()
    add_sysctl net.ipv4.tcp_congestion_control "$CONGESTION_CONTROL" && add_sysctl net.core.default_qdisc "$QDISC" || return 1
    add_at_least net.core.somaxconn "$SOMAXCONN" && add_at_least net.ipv4.tcp_max_syn_backlog "$MAX_SYN_BACKLOG" || return 1
    if [[ "$TUNE_BUFFERS" == yes ]]; then
        add_at_least net.core.rmem_max "$RMEM_MAX" && add_at_least net.core.wmem_max "$WMEM_MAX" || return 1
        # 只提高 autotuning 最大值，保留现有最小值/默认值，不全局放大初始分配。
        local key desired min default max extra
        for key in tcp_rmem tcp_wmem; do
            desired="$RMEM_MAX"; [[ "$key" != tcp_wmem ]] || desired="$WMEM_MAX"
            extra=$(sysctl -n "net.ipv4.$key") || return 1
            read -r min default max extra <<< "$extra"
            [[ -z "$extra" ]] && valid_uint "$min" 1 2147483647 && valid_uint "$default" 1 2147483647 && valid_uint "$max" 1 2147483647 || return 1
            (( 10#$max > desired )) && desired="$max"
            add_sysctl "net.ipv4.$key" "$min $default $desired" || return 1
        done
    fi
}
backup_configs() {
    local index current
    [[ ! -L "$BACKUP_ROOT" && ( ! -e "$BACKUP_ROOT" || ( -d "$BACKUP_ROOT" && -O "$BACKUP_ROOT" ) ) ]] || { log_error '备份根目录不是当前用户所有的普通目录'; return 1; }
    install -d -m 0700 "$BACKUP_ROOT" || return 1
    BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/change-$(date +%Y%m%d_%H%M%S)-XXXXXX") || return 1
    : > "$BACKUP_DIR/files.list" && : > "$BACKUP_DIR/runtime.tsv" || return 1
    for index in "${!SYSCTL_KEYS[@]}"; do
        current=$(sysctl -n "${SYSCTL_KEYS[$index]}") || return 1
        printf '%s\t%s\n' "${SYSCTL_KEYS[$index]}" "$current" >> "$BACKUP_DIR/runtime.tsv" || return 1
    done
    log_info "备份: $BACKUP_DIR"
}
backup_file() {
    local file="$1" saved="$BACKUP_DIR/files/${1#/}"
    [[ ! -L "$file" && ( ! -e "$file" || -f "$file" ) ]] || { log_error "拒绝链接/非普通文件: $file"; return 1; }
    [[ ! -e "$saved" && ! -e "$saved.absent" ]] || return 0
    mkdir -p "$(dirname "$saved")" || return 1
    if [[ -f "$file" ]]; then cp -p -- "$file" "$saved" || return 1; else : > "$saved.absent" || return 1; fi
    printf '%s\n' "$file" >> "$BACKUP_DIR/files.list"
}
atomic_write() {
    local file="$1" payload="$2" temp
    [[ ! -L "$file" && ( ! -e "$file" || -f "$file" ) ]] || return 1
    temp=$(mktemp "${file}.tmp.XXXXXX") || return 1
    if install -m 0644 -- "$payload" "$temp" && mv -f -- "$temp" "$file"; then return 0; fi
    rm -f -- "$temp"; return 1
}
generate_sysctl_config() {
    local temp index
    mkdir -p "$(dirname "$SYSCTL_FILE")" && backup_file "$SYSCTL_FILE" || return 1
    temp=$(mktemp "$BACKUP_DIR/sysctl.XXXXXX") || return 1
    { printf '# Managed by properties-script; %s\n' "$(date -Is)"
      for index in "${!SYSCTL_KEYS[@]}"; do printf '%s = %s\n' "${SYSCTL_KEYS[$index]}" "${SYSCTL_VALUES[$index]}"; done; } > "$temp" || return 1
    atomic_write "$SYSCTL_FILE" "$temp"
}
show_conflicts() {
    local key file index real own files=()
    local -A seen=()
    # 列出其他配置中的同键；不盲目修改或宣称重启后一定相同。
    # 按真实路径去重（99-sysctl.conf 常是 sysctl.conf 的链接；/lib 在 merged-usr 上即 /usr/lib），并覆盖未合并 /usr 的 /lib/sysctl.d。
    own=$(readlink -f -- "$SYSCTL_FILE")
    for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf; do
        [[ -f "$file" ]] || continue
        real=$(readlink -f -- "$file") || continue
        [[ "$real" != "$own" && -z "${seen[$real]:-}" ]] || continue
        seen[$real]=1; files+=("$file")
    done
    for index in "${!SYSCTL_KEYS[@]}"; do
        key="${SYSCTL_KEYS[$index]}"
        for file in "${files[@]}"; do
            awk -v key="$key" -v file="$file" '
                /^[[:space:]]*[#;]/ {next}
                {name=$0; sub(/=.*/,"",name); sub(/^[[:space:]]*-?/,"",name); sub(/[[:space:]].*/,"",name); gsub(/\//,".",name)}
                name==key {printf "[冲突候选] %s:%d: %s\n", file, NR, $0}
            ' "$file"
        done
    done
}
# 再次运行且选项变少时，旧专属文件中的键将不再持久化，但当前运行值不会自动撤回。
show_dropped_keys() {
    local key planned
    [[ -f "$SYSCTL_FILE" ]] || return 0
    while IFS= read -r key; do
        for planned in "${SYSCTL_KEYS[@]}"; do [[ "$key" != "$planned" ]] || continue 2; done
        log_warn "$key 将不再由本脚本持久化：当前运行值保持不变，重启后回到系统默认/其他配置；需立即撤回请用对应备份回滚"
    done < <(awk -F= '/^[[:space:]]*[^#;[:space:]]/ {gsub(/[[:space:]]/, "", $1); print $1}' "$SYSCTL_FILE")
}
configure_limits() {
    local temp nr_open hard soft current
    [[ "$PAM_LIMITS" == yes ]] || return 0
    nr_open=$(sysctl -n fs.nr_open) || return 1
    if ! valid_uint "$nr_open" 1 2147483647 || ! (( NOFILE <= 10#$nr_open )); then log_error '建议 nofile 超过内核 nr_open，不自动提高内核上限'; return 1; fi
    current=$(ulimit -Hn) || return 1
    if [[ "$current" == unlimited ]]; then hard="$nr_open"; else valid_uint "$current" 1 2147483647 || return 1; hard="$current"; fi
    (( 10#$hard < NOFILE )) && hard="$NOFILE"
    # 当前 nr_open 比既有限制低时拒绝，不偷偷降低现有 hard。
    (( 10#$hard <= 10#$nr_open )) || { log_error '现有 hard 超过 nr_open，请先人工统一限制'; return 1; }
    soft=$(ulimit -Sn) || return 1
    if [[ "$soft" == unlimited ]]; then soft="$hard"; else valid_uint "$soft" 1 2147483647 || return 1; fi
    (( 10#$soft < NOFILE )) && soft="$NOFILE"
    mkdir -p "$(dirname "$LIMITS_FILE")" && backup_file "$LIMITS_FILE" || return 1
    temp=$(mktemp "$BACKUP_DIR/limits.XXXXXX") || return 1
    printf '# Managed by properties-script; PAM new sessions only\n* soft nofile %s\n* hard nofile %s\nroot soft nofile %s\nroot hard nofile %s\n' "$soft" "$hard" "$soft" "$hard" > "$temp" || return 1
    atomic_write "$LIMITS_FILE" "$temp"
}
configure_service_limits() {
    local service hard soft nr_open file temp hard_value soft_value
    (( ${#SERVICE_NAMES[@]} )) || return 0
    validate_services || return 1
    nr_open=$(sysctl -n fs.nr_open) || return 1
    valid_uint "$nr_open" 1 2147483647 || return 1
    for service in "${SERVICE_NAMES[@]}"; do
        hard=$(systemctl show -p LimitNOFILE --value "$service") && soft=$(systemctl show -p LimitNOFILESoft --value "$service") || return 1
        hard_value="$hard"; soft_value="$soft"
        [[ "$hard" != infinity ]] || hard="$nr_open"
        [[ "$soft" != infinity ]] || soft="$nr_open"
        valid_uint "$hard" 1 2147483647 && valid_uint "$soft" 1 2147483647 || return 1
        (( 10#$hard < NOFILE )) && hard="$NOFILE"
        (( 10#$soft < NOFILE )) && soft="$NOFILE"
        (( 10#$hard <= 10#$nr_open && 10#$soft <= 10#$hard )) || { log_error "服务 $service 的限制与 nr_open 不兼容"; return 1; }
        file="$SERVICE_DROPIN_ROOT/$service.d/90-properties-script-nofile.conf"
        mkdir -p "$(dirname "$file")" && backup_file "$file" || return 1
        temp=$(mktemp "$BACKUP_DIR/service-limit.XXXXXX") || return 1
        [[ "$hard_value" == infinity ]] || hard_value="$hard"
        [[ "$soft_value" == infinity ]] || soft_value="$soft"
        printf '[Service]\nLimitNOFILE=%s:%s\n' "$soft_value" "$hard_value" > "$temp" || return 1
        atomic_write "$file" "$temp" || return 1
    done
    systemctl daemon-reload || return 1
    log_warn '服务 nofile 配置已写入，但现有进程没有变化。请在维护窗口重启所选服务。'
}
apply_config() {
    local index current expected
    for index in "${!SYSCTL_KEYS[@]}"; do
        sysctl -w "${SYSCTL_KEYS[$index]}=${SYSCTL_VALUES[$index]}" || return 1
        current=$(sysctl -n "${SYSCTL_KEYS[$index]}") || return 1
        # 向量参数的空格/tab 规范化后核对，不把 tab 差异当失败。
        current=$(awk '{$1=$1; print}' <<< "$current")
        expected=$(awk '{$1=$1; print}' <<< "${SYSCTL_VALUES[$index]}")
        [[ "$current" == "$expected" ]] || { log_error "${SYSCTL_KEYS[$index]} 未达到目标"; return 1; }
    done
}
rollback_config() {
    local file saved key value failed=0 reload=no
    [[ -f "$BACKUP_DIR/files.list" && -f "$BACKUP_DIR/runtime.tsv" ]] || return 1
    while IFS= read -r file; do
        saved="$BACKUP_DIR/files/${file#/}"
        if [[ -L "$file" ]]; then log_error "拒绝回滚到链接: $file"; failed=1; continue; fi
        if [[ -f "$saved.absent" ]]; then rm -f -- "$file" || failed=1
        elif [[ -f "$saved" ]]; then cp -p -- "$saved" "$file" || failed=1
        else log_error "缺少备份: $file"; failed=1
        fi
        [[ "$file" != "$SERVICE_DROPIN_ROOT"/* ]] || reload=yes
    done < "$BACKUP_DIR/files.list"
    while IFS=$'\t' read -r key value; do
        [[ -n "$key" ]] || continue
        sysctl -w "$key=$value" || failed=1
    done < "$BACKUP_DIR/runtime.tsv"
    if [[ "$reload" == yes ]]; then systemctl daemon-reload || failed=1; fi
    return "$failed"
}
validate_backup() {
    local file key value mode relative
    [[ "$(dirname "$BACKUP_DIR")" == "$BACKUP_ROOT" && "$(basename "$BACKUP_DIR")" == change-* && "$BACKUP_DIR" != *..* && ! -L "$BACKUP_ROOT" && -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || {
        log_error "备份目录必须是 $BACKUP_ROOT/change-* 的绝对路径: $BACKUP_DIR"; return 1; }
    [[ "$(stat -c %u "$BACKUP_DIR")" == 0 ]] || { log_error '回滚目录必须 root 所有、权限 700'; return 1; }
    mode=$(stat -c %a "$BACKUP_DIR") || return 1
    [[ "$mode" == 700 ]] || { log_error '回滚目录必须 root 所有、权限 700'; return 1; }
    [[ -f "$BACKUP_DIR/files.list" && ! -L "$BACKUP_DIR/files.list" && -f "$BACKUP_DIR/runtime.tsv" && ! -L "$BACKUP_DIR/runtime.tsv" ]] || { log_error '备份清单缺失或为链接'; return 1; }
    while IFS= read -r file; do
        if [[ "$file" != "$SYSCTL_FILE" && "$file" != "$LIMITS_FILE" ]]; then
            [[ "$file" == "$SERVICE_DROPIN_ROOT"/* ]] || return 1
            relative="${file#"$SERVICE_DROPIN_ROOT"/}"
            [[ "$relative" =~ ^[a-zA-Z0-9_:@.-]+\.service\.d/90-properties-script-nofile\.conf$ ]] || return 1
        fi
        [[ "$file" != *..* ]] || return 1
    done < "$BACKUP_DIR/files.list"
    while IFS=$'\t' read -r key value; do
        case "$key" in net.ipv4.tcp_congestion_control|net.core.default_qdisc|net.core.somaxconn|net.ipv4.tcp_max_syn_backlog|net.core.rmem_max|net.core.wmem_max|net.ipv4.tcp_rmem|net.ipv4.tcp_wmem) ;; *) return 1 ;; esac
        [[ -n "$value" && "$value" != *$'\n'* ]] || return 1
    done < "$BACKUP_DIR/runtime.tsv"
}
verify_config() {
    local service pid root_qdisc
    log_title '验收'
    sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc || return 1
    log_info "新建 TCP 连接立即使用 ${CONGESTION_CONTROL}；已有连接与监听 socket 保持原算法，相关服务重启后生效"
    if ! command -v tc >/dev/null 2>&1; then
        log_warn '未安装 tc，无法查看实际网卡队列'
    elif [[ -n "$NET_IFACE" ]]; then
        tc -s qdisc show dev "$NET_IFACE" || return 1
        root_qdisc=$(tc qdisc show dev "$NET_IFACE" root 2>/dev/null | awk 'NR == 1 {print $2}')
        # default_qdisc 只影响之后新建的队列；本脚本不替换正在使用的队列，只给出命令。
        if [[ "$root_qdisc" == mq ]]; then
            log_info "$NET_IFACE 为多队列（mq），各子队列在重启或网卡重新初始化后改用 ${QDISC}"
        elif [[ -n "$root_qdisc" && "$root_qdisc" != "$QDISC" ]]; then
            log_info "$NET_IFACE 当前队列为 ${root_qdisc}；立即切换（会短暂影响该网卡流量）: tc qdisc replace dev $NET_IFACE root $QDISC"
        fi
        [[ "$CONGESTION_CONTROL" != bbr* ]] || log_info 'BBR 在 4.13+ 内核自带 pacing，队列未切换前也能生效'
    else
        tc -s qdisc show || return 1
    fi
    for service in "${SERVICE_NAMES[@]}"; do
        pid=$(systemctl show -p MainPID --value "$service") || return 1
        log_info "$service 当前主进程 PID=$pid"
        if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/limits" ]]; then grep 'Max open files' "/proc/$pid/limits" || return 1; fi
    done
    log_info '请对比业务吞吐、延迟、重传和内存；参数已应用不等于性能已改善。'
}
# 回滚的是“该次变更之前”的状态；若之后还有变更，应按时间倒序逐个回滚。
warn_newer_backups() {
    local dir newer=()
    [[ ! -e "$BACKUP_DIR/$ROLLED_BACK_MARK" ]] || log_warn "该备份已于 $(cat "$BACKUP_DIR/$ROLLED_BACK_MARK" 2>/dev/null) 回滚过，将再次恢复"
    # 按修改时间比较（目录名同一秒内只靠随机后缀，无法排序）；已回滚的备份不再提示。
    for dir in "$BACKUP_ROOT"/change-*; do
        [[ -d "$dir" && "$dir" -nt "$BACKUP_DIR" && ! -e "$dir/$ROLLED_BACK_MARK" ]] && newer+=("$dir")
    done
    (( ${#newer[@]} == 0 )) && return 0
    log_warn '存在更晚的变更备份；建议先按时间倒序回滚它们（其服务 drop-in 不在本次回滚范围内）：'
    printf '  %s\n' "${newer[@]}" >&2
}
main() {
    local index current
    case "${1:-}" in
        --help|-h) printf '%s\n' 'sudo bash optimize-vps.sh' 'sudo bash optimize-vps.sh --rollback /var/backups/properties-script-vps/change-...'; return 0 ;;
        --rollback)
            [[ $# == 2 ]] || { log_error '用法: sudo bash optimize-vps.sh --rollback /var/backups/properties-script-vps/change-...'; return 1; }
            check_rollback_system && acquire_lock || return 1
            BACKUP_DIR="${2%/}"
            validate_backup || { log_error '备份不合法'; return 1; }
            warn_newer_backups
            rollback_config || { log_error '回滚失败，请核对上方错误'; return 1; }
            # 标记写在备份目录内（不影响 validate_backup）；保留目录原修改时间，warn_newer_backups 依赖它排序。
            current=$(stat -c %y -- "$BACKUP_DIR") || current=
            date -Is > "$BACKUP_DIR/$ROLLED_BACK_MARK" || log_warn '无法写入回滚标记'
            [[ -z "$current" ]] || touch -d "$current" -- "$BACKUP_DIR" || log_warn '无法恢复备份目录时间戳'
            log_info '持久化文件及原 sysctl 运行值已恢复；不会自动重启业务服务或卸载模块'; return 0 ;;
        '') ;;
        *) log_error '未知参数'; return 1 ;;
    esac
    check_system && acquire_lock && check_legacy_config && detect_system && calculate_params || return 1
    [[ -t 0 ]] || { log_error '需要交互终端'; return 1; }
    ask_user_params || return 1
    confirm '确认加载所选模块并准备变更计划？' || return 0
    check_kernel_support && build_sysctl_plan || return 1
    for index in "${!SYSCTL_KEYS[@]}"; do
        current=$(sysctl -n "${SYSCTL_KEYS[$index]}") || return 1
        printf '%s: %s -> %s\n' "${SYSCTL_KEYS[$index]}" "$current" "${SYSCTL_VALUES[$index]}"
    done
    show_conflicts || return 1
    show_dropped_keys
    confirm '确认应用以上参数及选定 nofile 配置？' || return 0
    # 备份→写入→应用→失败回滚期间没有交互，忽略中断/断线，避免停在“文件已写、运行值未改或半改”的状态。
    trap '' HUP INT TERM
    backup_configs || { trap - HUP INT TERM; return 1; }
    if ! generate_sysctl_config || ! configure_limits || ! configure_service_limits || ! apply_config; then
        log_error '应用失败，恢复文件及变更前的运行参数'
        rollback_config || log_error "自动回滚失败，请核对备份: $BACKUP_DIR"
        trap - HUP INT TERM
        return 1
    fi
    trap - HUP INT TERM
    verify_config || { log_error '参数已应用，但验收失败；请检查输出或执行回滚'; return 1; }
    log_info "应用完成。回滚命令: sudo bash $0 --rollback $BACKUP_DIR"
    log_warn 'PAM 限额需新登录；服务限额需维护窗口重启；其他 sysctl 配置可能影响下次启动，请核对冲突。'
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    main "$@"
fi
