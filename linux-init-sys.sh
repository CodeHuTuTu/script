#!/bin/bash

# Linux System Initialization Script
# Author: CodeHuTuTu
# Description: Automated setup script for Linux systems

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Detect OS distribution
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/redhat-release ]]; then
        OS=RedHat
        VER=$(cat /etc/redhat-release | cut -d ' ' -f 3)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    log "Detected OS: $OS $VER"
}

# Update system packages
update_system() {
    log "Updating system packages..."
    
    case $OS in
        *Ubuntu*|*Debian*)
            apt update && apt upgrade -y
            ;;
        *CentOS*|*RedHat*|*Fedora*)
            if command -v dnf &> /dev/null; then
                dnf update -y
            else
                yum update -y
            fi
            ;;
        *Arch*)
            pacman -Syu --noconfirm
            ;;
        *)
            warning "Unsupported OS for automatic updates: $OS"
            ;;
    esac
}

# Install essential packages
install_essentials() {
    log "Installing essential packages..."
    
    case $OS in
        *Ubuntu*|*Debian*)
            apt install -y curl wget git vim nano htop tree unzip build-essential
            ;;
        *CentOS*|*RedHat*|*Fedora*)
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget git vim nano htop tree unzip gcc gcc-c++ make
            else
                yum install -y curl wget git vim nano htop tree unzip gcc gcc-c++ make
            fi
            ;;
        *Arch*)
            pacman -S --noconfirm curl wget git vim nano htop tree unzip base-devel
            ;;
        *)
            warning "Unsupported OS for automatic package installation: $OS"
            ;;
    esac
}

# Configure shell aliases
configure_aliases() {
    log "Configuring shell aliases..."
    
    cat >> ~/.bashrc << 'EOF'

# Custom aliases
alias ll='ls -l --color=auto'
alias la='ls -la --color=auto'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias h='history'
alias c='clear'
alias df='df -h'
alias du='du -h'
alias free='free -h'
alias ps='ps aux'
alias ports='netstat -tuln'
alias mount='mount | column -t'
EOF
}

# Configure vim
configure_vim() {
    log "Configuring vim..."
    
    cat > ~/.vimrc << 'EOF'
" Basic vim configuration
set number
set relativenumber
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set smartindent
set hlsearch
set incsearch
set ignorecase
set smartcase
set wrap
set linebreak
set noswapfile
set nobackup
set undodir=~/.vim/undodir
set undofile
set clipboard=unnamedplus
syntax enable
colorscheme desert

" Key mappings
nnoremap <C-s> :w<CR>
nnoremap <C-q> :q<CR>
nnoremap <C-a> ggVG
vnoremap <C-c> "+y
nnoremap <C-v> "+p

" Status line
set laststatus=2
set statusline=%F%m%r%h%w\ [FORMAT=%{&ff}]\ [TYPE=%Y]\ [POS=%l,%v][%p%%]\ %{strftime(\"%d/%m/%y\ -\ %H:%M\")}
EOF

    # Create undodir if it doesn't exist
    mkdir -p ~/.vim/undodir
}

# Configure git (if not already configured)
configure_git() {
    log "Configuring git..."
    
    if ! git config --global user.name &> /dev/null; then
        read -p "Enter your git username: " git_username
        git config --global user.name "$git_username"
    fi
    
    if ! git config --global user.email &> /dev/null; then
        read -p "Enter your git email: " git_email
        git config --global user.email "$git_email"
    fi
    
    git config --global init.defaultBranch main
    git config --global core.editor vim
    git config --global pull.rebase false
}

# Setup SSH keys
setup_ssh() {
    log "Setting up SSH configuration..."
    
    if [[ ! -d ~/.ssh ]]; then
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
    fi
    
    if [[ ! -f ~/.ssh/id_rsa ]]; then
        read -p "Generate new SSH key? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "Enter email for SSH key: " ssh_email
            ssh-keygen -t rsa -b 4096 -C "$ssh_email" -f ~/.ssh/id_rsa
            log "SSH key generated. Public key:"
            cat ~/.ssh/id_rsa.pub
        fi
    fi
    
    # Configure SSH client
    cat > ~/.ssh/config << 'EOF'
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking ask
    VerifyHostKeyDNS yes
EOF
    chmod 600 ~/.ssh/config
}

# Configure firewall (UFW for Ubuntu/Debian, firewalld for RHEL/CentOS)
configure_firewall() {
    log "Configuring firewall..."
    
    case $OS in
        *Ubuntu*|*Debian*)
            if ! command -v ufw &> /dev/null; then
                apt install -y ufw
            fi
            ufw --force enable
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ;;
        *CentOS*|*RedHat*|*Fedora*)
            if ! systemctl is-active --quiet firewalld; then
                systemctl enable firewalld
                systemctl start firewalld
            fi
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --reload
            ;;
        *)
            warning "Firewall configuration not supported for: $OS"
            ;;
    esac
}

# Configure system security
configure_security() {
    log "Configuring system security..."
    
    # Disable root login via SSH
    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    fi
    
    # Disable password authentication (uncomment if you want key-only auth)
    # sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Configure automatic security updates
    case $OS in
        *Ubuntu*|*Debian*)
            apt install -y unattended-upgrades
            dpkg-reconfigure -plow unattended-upgrades
            ;;
        *CentOS*|*RedHat*|*Fedora*)
            if command -v dnf &> /dev/null; then
                dnf install -y dnf-automatic
                systemctl enable --now dnf-automatic.timer
            else
                yum install -y yum-cron
                systemctl enable --now yum-cron
            fi
            ;;
    esac
    
    # Restart SSH service
    systemctl restart ssh || systemctl restart sshd
}

# Setup monitoring tools
setup_monitoring() {
    log "Setting up monitoring tools..."
    
    # Install and configure htop
    if ! command -v htop &> /dev/null; then
        case $OS in
            *Ubuntu*|*Debian*)
                apt install -y htop
                ;;
            *CentOS*|*RedHat*|*Fedora*)
                if command -v dnf &> /dev/null; then
                    dnf install -y htop
                else
                    yum install -y htop
                fi
                ;;
        esac
    fi
    
    # Install iostat, vmstat (part of sysstat)
    case $OS in
        *Ubuntu*|*Debian*)
            apt install -y sysstat
            ;;
        *CentOS*|*RedHat*|*Fedora*)
            if command -v dnf &> /dev/null; then
                dnf install -y sysstat
            else
                yum install -y sysstat
            fi
            ;;
    esac
}

# Configure system limits
configure_limits() {
    log "Configuring system limits..."
    
    cat >> /etc/security/limits.conf << 'EOF'
# Custom limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
EOF
}

# Setup log rotation
setup_logrotate() {
    log "Setting up log rotation..."
    
    cat > /etc/logrotate.d/custom-logs << 'EOF'
/var/log/custom/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
}

# Install Docker (optional)
install_docker() {
    read -p "Install Docker? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Installing Docker..."
        
        case $OS in
            *Ubuntu*|*Debian*)
                curl -fsSL https://get.docker.com -o get-docker.sh
                sh get-docker.sh
                usermod -aG docker $SUDO_USER 2>/dev/null || true
                ;;
            *CentOS*|*RedHat*|*Fedora*)
                if command -v dnf &> /dev/null; then
                    dnf install -y docker
                else
                    yum install -y docker
                fi
                systemctl enable --now docker
                usermod -aG docker $SUDO_USER 2>/dev/null || true
                ;;
            *)
                warning "Docker installation not supported for: $OS"
                ;;
        esac
        
        rm -f get-docker.sh
    fi
}

# Install Node.js and npm (optional)
install_nodejs() {
    read -p "Install Node.js and npm? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Installing Node.js and npm..."
        
        # Install Node.js via NodeSource repository
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
        
        case $OS in
            *Ubuntu*|*Debian*)
                apt install -y nodejs
                ;;
            *CentOS*|*RedHat*|*Fedora*)
                if command -v dnf &> /dev/null; then
                    dnf install -y nodejs npm
                else
                    yum install -y nodejs npm
                fi
                ;;
            *)
                warning "Node.js installation not supported for: $OS"
                ;;
        esac
    fi
}

# Install Python pip and common packages (optional)
install_python_tools() {
    read -p "Install Python pip and common packages? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Installing Python tools..."
        
        case $OS in
            *Ubuntu*|*Debian*)
                apt install -y python3-pip python3-venv
                ;;
            *CentOS*|*RedHat*|*Fedora*)
                if command -v dnf &> /dev/null; then
                    dnf install -y python3-pip
                else
                    yum install -y python3-pip
                fi
                ;;
            *)
                warning "Python tools installation not supported for: $OS"
                ;;
        esac
        
        # Install common Python packages
        pip3 install --upgrade pip
        pip3 install virtualenv requests numpy pandas matplotlib
    fi
}

# Setup development environment
setup_dev_environment() {
    read -p "Setup development environment? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Setting up development environment..."
        
        # Create common directories
        mkdir -p ~/projects ~/scripts ~/bin
        
        # Add ~/bin to PATH if not already there
        if ! echo $PATH | grep -q "$HOME/bin"; then
            echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
        fi
        
        # Install additional development tools
        case $OS in
            *Ubuntu*|*Debian*)
                apt install -y code || true  # VS Code (if available)
                apt install -y tmux screen
                ;;
            *CentOS*|*RedHat*|*Fedora*)
                if command -v dnf &> /dev/null; then
                    dnf install -y tmux screen
                else
                    yum install -y tmux screen
                fi
                ;;
        esac
    fi
}

# Cleanup function
cleanup() {
    log "Performing cleanup..."
    
    case $OS in
        *Ubuntu*|*Debian*)
            apt autoremove -y
            apt autoclean
            ;;
        *CentOS*|*RedHat*|*Fedora*)
            if command -v dnf &> /dev/null; then
                dnf autoremove -y
                dnf clean all
            else
                yum autoremove -y
                yum clean all
            fi
            ;;
    esac
}

# Create system info script
create_system_info_script() {
    log "Creating system info script..."
    
    cat > ~/bin/sysinfo << 'EOF'
#!/bin/bash
echo "=== System Information ==="
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo ""
echo "=== Memory Usage ==="
free -h
echo ""
echo "=== Disk Usage ==="
df -h | grep -v tmpfs
echo ""
echo "=== Network Interfaces ==="
ip -br addr show
echo ""
echo "=== Active Services ==="
systemctl list-units --type=service --state=running --no-pager | head -10
EOF
    
    chmod +x ~/bin/sysinfo
}

# Main function
main() {
    log "Starting Linux system initialization..."
    
    detect_os
    update_system
    install_essentials
    configure_aliases
    configure_vim
    configure_git
    setup_ssh
    configure_firewall
    configure_security
    setup_monitoring
    configure_limits
    setup_logrotate
    create_system_info_script
    
    # Optional installations
    install_docker
    install_nodejs
    install_python_tools
    setup_dev_environment
    
    cleanup
    
    log "System initialization completed successfully!"
    log "Please reboot the system or source ~/.bashrc to apply all changes"
    log "Run 'sysinfo' command to view system information"
    
    warning "Important: If you disabled password authentication for SSH, make sure you have SSH key access before logging out!"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi