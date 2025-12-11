#!/bin/bash

# Linux System Initialization Script
# Author: CodeHuTuTu
# Last Updated: 2025-12-11

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons."
        exit 1
    fi
}

# Function to update system packages
update_system() {
    print_header "Updating System Packages"
    
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt upgrade -y
    elif command -v yum &> /dev/null; then
        sudo yum update -y
    elif command -v dnf &> /dev/null; then
        sudo dnf update -y
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm
    else
        print_error "Unsupported package manager"
        return 1
    fi
    
    print_status "System packages updated successfully"
}

# Function to install essential packages
install_essentials() {
    print_header "Installing Essential Packages"
    
    local packages="curl wget git vim htop tree unzip zip build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y $packages
    elif command -v yum &> /dev/null; then
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y curl wget git vim htop tree unzip zip
    elif command -v dnf &> /dev/null; then
        sudo dnf groupinstall -y "Development Tools"
        sudo dnf install -y curl wget git vim htop tree unzip zip
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm curl wget git vim htop tree unzip zip base-devel
    fi
    
    print_status "Essential packages installed successfully"
}

# Function to configure shell aliases
configure_aliases() {
    print_header "Configuring Shell Aliases"
    
    # Create or update .bash_aliases
    cat >> ~/.bash_aliases << 'EOF'
# Custom aliases
alias ll='ls -lh --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias h='history'
alias c='clear'
alias df='df -h'
alias du='du -h'
alias free='free -h'
alias ps='ps auxf'
alias mkdir='mkdir -pv'
alias wget='wget -c'
alias myip='curl -s https://ipinfo.io/ip'
EOF

    # Add source to .bashrc if not already present
    if ! grep -q "source ~/.bash_aliases" ~/.bashrc; then
        echo "source ~/.bash_aliases" >> ~/.bashrc
    fi
    
    print_status "Shell aliases configured successfully"
}

# Function to setup Git configuration
setup_git() {
    print_header "Setting up Git Configuration"
    
    read -p "Enter your Git username: " git_username
    read -p "Enter your Git email: " git_email
    
    git config --global user.name "$git_username"
    git config --global user.email "$git_email"
    git config --global init.defaultBranch main
    git config --global pull.rebase false
    
    print_status "Git configured successfully"
}

# Function to install and configure fail2ban with whitelist
install_fail2ban() {
    print_header "Installing and Configuring Fail2ban"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y fail2ban
    elif command -v yum &> /dev/null; then
        sudo yum install -y epel-release
        sudo yum install -y fail2ban
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y fail2ban
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm fail2ban
    fi
    
    # Create fail2ban local configuration
    sudo tee /etc/fail2ban/jail.local > /dev/null << 'EOF'
[DEFAULT]
# Ban time in seconds (1 hour)
bantime = 3600

# Find time in seconds (10 minutes)
findtime = 600

# Number of failures before ban
maxretry = 5

# Whitelist IPs (localhost and private networks by default)
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

    # Prompt for additional whitelist IPs
    echo
    print_warning "Configure Fail2ban IP Whitelist"
    read -p "Enter additional IPs to whitelist (space-separated, or press Enter to skip): " whitelist_ips
    
    if [[ -n "$whitelist_ips" ]]; then
        # Add custom IPs to the ignore list
        sudo sed -i "s/ignoreip = .*/& $whitelist_ips/" /etc/fail2ban/jail.local
        print_status "Added IPs to whitelist: $whitelist_ips"
    fi
    
    # Enable and start fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    
    print_status "Fail2ban installed and configured with IP whitelist"
}

# Function to configure firewall
configure_firewall() {
    print_header "Configuring UFW Firewall"
    
    if ! command -v ufw &> /dev/null; then
        if command -v apt &> /dev/null; then
            sudo apt install -y ufw
        else
            print_warning "UFW not available on this system"
            return 1
        fi
    fi
    
    # Configure UFW
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    
    read -p "Do you want to enable UFW firewall now? (y/N): " enable_ufw
    if [[ $enable_ufw =~ ^[Yy]$ ]]; then
        sudo ufw --force enable
        print_status "UFW firewall enabled"
    else
        print_warning "UFW firewall configured but not enabled"
    fi
}

# Function to setup SSH key
setup_ssh_key() {
    print_header "Setting up SSH Key"
    
    if [[ -f ~/.ssh/id_rsa ]] || [[ -f ~/.ssh/id_ed25519 ]]; then
        print_warning "SSH key already exists"
        read -p "Do you want to generate a new SSH key? (y/N): " generate_new
        if [[ ! $generate_new =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    read -p "Enter your email for SSH key: " ssh_email
    read -p "Choose key type (1: RSA, 2: Ed25519) [2]: " key_type
    
    case $key_type in
        1)
            ssh-keygen -t rsa -b 4096 -C "$ssh_email" -f ~/.ssh/id_rsa
            ;;
        *)
            ssh-keygen -t ed25519 -C "$ssh_email" -f ~/.ssh/id_ed25519
            ;;
    esac
    
    print_status "SSH key generated successfully"
    print_status "Public key content:"
    if [[ -f ~/.ssh/id_ed25519.pub ]]; then
        cat ~/.ssh/id_ed25519.pub
    elif [[ -f ~/.ssh/id_rsa.pub ]]; then
        cat ~/.ssh/id_rsa.pub
    fi
}

# Function to install Docker
install_docker() {
    print_header "Installing Docker"
    
    # Remove old versions
    if command -v apt &> /dev/null; then
        sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Add Docker repository
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        sudo apt update
        sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        print_error "Docker installation script currently supports Ubuntu/Debian only"
        return 1
    fi
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    # Enable and start Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    print_status "Docker installed successfully"
    print_warning "Please log out and log back in for Docker group changes to take effect"
}

# Function to optimize system performance
optimize_system() {
    print_header "Optimizing System Performance"
    
    # Configure swappiness
    echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
    
    # Configure file descriptor limits
    echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
    echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf
    
    # Configure network settings
    cat | sudo tee -a /etc/sysctl.conf << 'EOF'
# Network optimizations
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
    
    # Apply sysctl changes
    sudo sysctl -p
    
    print_status "System performance optimized"
}

# Function for more advanced options
more_options_menu() {
    while true; do
        print_header "More Options - Advanced System Configuration"
        echo "1. Configure Automatic Security Updates"
        echo "2. Install and Configure Nginx"
        echo "3. Setup System Monitoring (htop, iotop, nethogs)"
        echo "4. Configure Log Rotation"
        echo "5. Install Development Tools (Node.js, Python pip, etc.)"
        echo "6. Setup Backup Directory Structure"
        echo "7. Configure Time Synchronization (NTP)"
        echo "8. Install and Configure Zsh with Oh My Zsh"
        echo "9. Setup System Resource Limits"
        echo "10. Configure Network Tools (nmap, netstat, ss)"
        echo "0. Return to Main Menu"
        echo
        
        read -p "Select an option: " choice
        
        case $choice in
            1) configure_auto_updates ;;
            2) install_nginx ;;
            3) install_monitoring_tools ;;
            4) configure_log_rotation ;;
            5) install_dev_tools ;;
            6) setup_backup_structure ;;
            7) configure_ntp ;;
            8) install_zsh_ohmyzsh ;;
            9) configure_resource_limits ;;
            10) install_network_tools ;;
            0) break ;;
            *) print_error "Invalid option. Please try again." ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

# Advanced option functions
configure_auto_updates() {
    print_header "Configuring Automatic Security Updates"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y unattended-upgrades
        
        # Configure unattended-upgrades
        sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        
        # Enable automatic updates
        sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        
        print_status "Automatic security updates configured"
    else
        print_error "Automatic updates configuration only available for apt-based systems"
    fi
}

install_nginx() {
    print_header "Installing and Configuring Nginx"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y nginx
        
        # Basic security configuration
        sudo tee /etc/nginx/conf.d/security.conf > /dev/null << 'EOF'
# Hide nginx version
server_tokens off;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
EOF
        
        sudo systemctl enable nginx
        sudo systemctl start nginx
        
        print_status "Nginx installed and configured with basic security"
    else
        print_error "Nginx installation currently supports apt-based systems only"
    fi
}

install_monitoring_tools() {
    print_header "Installing System Monitoring Tools"
    
    local tools="htop iotop nethogs glances ncdu"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y $tools
    elif command -v yum &> /dev/null; then
        sudo yum install -y $tools
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y $tools
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm $tools
    fi
    
    print_status "Monitoring tools installed: htop, iotop, nethogs, glances, ncdu"
}

configure_log_rotation() {
    print_header "Configuring Log Rotation"
    
    # Custom logrotate configuration
    sudo tee /etc/logrotate.d/custom-logs > /dev/null << 'EOF'
/var/log/custom/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
    
    # Create custom log directory
    sudo mkdir -p /var/log/custom
    
    print_status "Custom log rotation configured"
}

install_dev_tools() {
    print_header "Installing Development Tools"
    
    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt install -y nodejs
    
    # Install Python pip and development packages
    if command -v apt &> /dev/null; then
        sudo apt install -y python3-pip python3-dev python3-venv
    fi
    
    # Install useful development packages
    sudo npm install -g yarn pm2
    pip3 install --user virtualenv pipenv
    
    print_status "Development tools installed (Node.js, npm, yarn, pip, virtualenv)"
}

setup_backup_structure() {
    print_header "Setting up Backup Directory Structure"
    
    mkdir -p ~/backups/{daily,weekly,monthly}
    mkdir -p ~/backups/configs
    mkdir -p ~/backups/databases
    mkdir -p ~/backups/files
    
    # Create a simple backup script template
    cat > ~/backups/backup-template.sh << 'EOF'
#!/bin/bash
# Backup script template
# Customize as needed

BACKUP_DIR="$HOME/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Example: Backup home directory (excluding backups folder)
# tar -czf "$BACKUP_DIR/daily/home_backup_$DATE.tar.gz" --exclude="$BACKUP_DIR" "$HOME"

echo "Backup completed: $DATE"
EOF
    
    chmod +x ~/backups/backup-template.sh
    
    print_status "Backup directory structure created in ~/backups/"
}

configure_ntp() {
    print_header "Configuring Time Synchronization (NTP)"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y chrony
        sudo systemctl enable chrony
        sudo systemctl start chrony
        
        # Check time synchronization status
        chrony sources -v
        
        print_status "NTP/Chrony configured and running"
    else
        print_error "NTP configuration currently supports apt-based systems only"
    fi
}

install_zsh_ohmyzsh() {
    print_header "Installing Zsh with Oh My Zsh"
    
    # Install zsh
    if command -v apt &> /dev/null; then
        sudo apt install -y zsh
    elif command -v yum &> /dev/null; then
        sudo yum install -y zsh
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y zsh
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm zsh
    fi
    
    # Install Oh My Zsh
    sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    
    print_status "Zsh and Oh My Zsh installed. Run 'chsh -s $(which zsh)' to change default shell"
}

configure_resource_limits() {
    print_header "Configuring System Resource Limits"
    
    # Configure limits for all users
    sudo tee -a /etc/security/limits.conf > /dev/null << 'EOF'
# Custom resource limits
* soft core 0
* hard core 0
* soft nproc 65536
* hard nproc 65536
* soft memlock unlimited
* hard memlock unlimited
EOF
    
    # Configure systemd user limits
    sudo mkdir -p /etc/systemd/user.conf.d
    sudo tee /etc/systemd/user.conf.d/limits.conf > /dev/null << 'EOF'
[Manager]
DefaultLimitNOFILE=65536
DefaultLimitNPROC=65536
EOF
    
    print_status "System resource limits configured"
}

install_network_tools() {
    print_header "Installing Network Tools"
    
    local tools="nmap netstat-nat tcpdump wireshark-common dnsutils traceroute mtr-tiny"
    
    if command -v apt &> /dev/null; then
        sudo apt install -y $tools
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap net-tools tcpdump bind-utils traceroute mtr
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y nmap net-tools tcpdump bind-utils traceroute mtr
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm nmap net-tools tcpdump bind-tools traceroute mtr
    fi
    
    print_status "Network tools installed: nmap, netstat, tcpdump, dig, traceroute, mtr"
}

# Main menu function
show_menu() {
    clear
    print_header "Linux System Initialization Script"
    echo "Author: CodeHuTuTu"
    echo "Last Updated: 2025-12-11"
    echo
    echo "Select an option:"
    echo "1. Update System Packages"
    echo "2. Install Essential Packages"
    echo "3. Configure Shell Aliases"
    echo "4. Setup Git Configuration"
    echo "5. Install and Configure Fail2ban (with IP whitelist)"
    echo "6. Configure UFW Firewall"
    echo "7. Setup SSH Key"
    echo "8. Install Docker"
    echo "9. Optimize System Performance"
    echo "10. More Options (Advanced Configuration)"
    echo "11. Run All Basic Setup (1-6,9)"
    echo "0. Exit"
    echo
}

# Function to run all basic setup
run_all_basic() {
    print_header "Running All Basic Setup Options"
    update_system
    install_essentials
    configure_aliases
    setup_git
    install_fail2ban
    configure_firewall
    optimize_system
    print_status "All basic setup completed!"
}

# Main script execution
main() {
    # Check if not running as root
    check_root
    
    while true; do
        show_menu
        read -p "Enter your choice: " choice
        
        case $choice in
            1) update_system ;;
            2) install_essentials ;;
            3) configure_aliases ;;
            4) setup_git ;;
            5) install_fail2ban ;;
            6) configure_firewall ;;
            7) setup_ssh_key ;;
            8) install_docker ;;
            9) optimize_system ;;
            10) more_options_menu ;;
            11) run_all_basic ;;
            0) 
                print_status "Exiting script. Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@"