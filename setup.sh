#!/usr/bin/env bash
# ============================================================================
# HexStrike AI Red Team Framework v6.0 — Master Setup Script
# ============================================================================
#
# One-shot installer for ALL HexStrike dependencies including:
#   - Python packages (pip)
#   - System security tools (apt)
#   - Go-based security tools (go install)
#   - Ruby gems (gem install)
#   - Browser automation (Chromium + ChromeDriver)
#   - Optional: BOAZ evasion compile chain
#   - Optional: Cloud security tools
#   - Optional: Deep forensics tools
#
# USAGE:
#   chmod +x setup.sh
#   sudo ./setup.sh                   # Core install (~60 tools)
#   sudo ./setup.sh --full            # Everything (~150+ tools)
#   sudo ./setup.sh --minimal         # Python deps + 15 essential tools only
#   sudo ./setup.sh --with-boaz       # Core + BOAZ evasion framework
#   sudo ./setup.sh --with-cloud      # Core + cloud security tools
#   sudo ./setup.sh --with-forensics  # Core + deep forensics tools
#   sudo ./setup.sh --full --with-boaz  # Combine flags freely
#
# SUPPORTED OS:
#   - Kali Linux (recommended, most tools in repos)
#   - Debian 12+ / Ubuntu 22.04+
#   - ParrotOS
#
# ============================================================================

set -euo pipefail

# ============================================================================
# COLOR CODES & LOGGING
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

LOGFILE="/tmp/hexstrike_setup_$(date +%Y%m%d_%H%M%S).log"
FAILED_PACKAGES=()
INSTALLED_COUNT=0
SKIPPED_COUNT=0
FAILED_COUNT=0

log_info()    { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOGFILE"; }
log_warn()    { echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$LOGFILE"; }
log_error()   { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOGFILE"; }
log_section() { echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOGFILE"
                echo -e "${CYAN}${BOLD}  $1${NC}" | tee -a "$LOGFILE"
                echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n" | tee -a "$LOGFILE"; }
log_subsection() { echo -e "\n${MAGENTA}  ▸ $1${NC}" | tee -a "$LOGFILE"; }

# ============================================================================
# FLAG PARSING
# ============================================================================
INSTALL_FULL=false
INSTALL_MINIMAL=false
INSTALL_BOAZ=false
INSTALL_CLOUD=false
INSTALL_FORENSICS=false
SKIP_CONFIRM=false

for arg in "$@"; do
    case "$arg" in
        --full)         INSTALL_FULL=true ;;
        --minimal)      INSTALL_MINIMAL=true ;;
        --with-boaz)    INSTALL_BOAZ=true ;;
        --with-cloud)   INSTALL_CLOUD=true ;;
        --with-forensics) INSTALL_FORENSICS=true ;;
        -y|--yes)       SKIP_CONFIRM=true ;;
        --help|-h)
            echo "HexStrike Setup Script v6.0"
            echo ""
            echo "Usage: sudo ./setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  (no flags)        Core install (~60 tools)"
            echo "  --minimal         Python deps + 15 essential tools only"
            echo "  --full            Everything (~150+ tools)"
            echo "  --with-boaz       Include BOAZ evasion framework compile chain"
            echo "  --with-cloud      Include cloud security tools (prowler, trivy, etc.)"
            echo "  --with-forensics  Include deep forensics tools (volatility, autopsy, etc.)"
            echo "  -y, --yes         Skip confirmation prompts"
            echo "  -h, --help        Show this help message"
            echo ""
            echo "Combine flags: sudo ./setup.sh --full --with-boaz --with-cloud"
            exit 0
            ;;
        *)
            log_error "Unknown option: $arg"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# --full implies all optional modules
if [ "$INSTALL_FULL" = true ]; then
    INSTALL_CLOUD=true
    INSTALL_FORENSICS=true
fi

# ============================================================================
# ROOT CHECK
# ============================================================================
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo ./setup.sh)"
    exit 1
fi

# Determine the real user (for go/gem installs in user space)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ============================================================================
# OS DETECTION
# ============================================================================
log_section "🔍 SYSTEM DETECTION"

OS_ID="unknown"
OS_VERSION=""
IS_KALI=false
IS_DEBIAN=false
IS_PARROT=false

if [ -f /etc/os-release ]; then
    source /etc/os-release
    OS_ID="$ID"
    OS_VERSION="${VERSION_ID:-rolling}"
fi

case "$OS_ID" in
    kali)     IS_KALI=true;   log_info "Detected: Kali Linux ($OS_VERSION) — Best compatibility ✓" ;;
    parrot)   IS_PARROT=true; log_info "Detected: ParrotOS ($OS_VERSION) — Good compatibility ✓" ;;
    debian)   IS_DEBIAN=true; log_info "Detected: Debian ($OS_VERSION) — Some tools may need manual install" ;;
    ubuntu)   IS_DEBIAN=true; log_info "Detected: Ubuntu ($OS_VERSION) — Some tools may need manual install" ;;
    *)        log_warn "Detected: $OS_ID — Untested OS, proceeding anyway..." ;;
esac

log_info "Architecture: $(uname -m)"
log_info "Kernel: $(uname -r)"
log_info "Log file: $LOGFILE"

# ============================================================================
# INSTALLATION SUMMARY & CONFIRMATION
# ============================================================================
log_section "📋 INSTALLATION PLAN"

if [ "$INSTALL_MINIMAL" = true ]; then
    echo -e "  ${BOLD}Mode:${NC} MINIMAL — Python deps + 15 essential tools"
elif [ "$INSTALL_FULL" = true ]; then
    echo -e "  ${BOLD}Mode:${NC} FULL — All 150+ tools + all optional modules"
else
    echo -e "  ${BOLD}Mode:${NC} CORE — ~60 most-used security tools"
fi

echo -e "  ${BOLD}BOAZ evasion:${NC}    $([ "$INSTALL_BOAZ" = true ] && echo '✓ YES' || echo '✗ No')"
echo -e "  ${BOLD}Cloud tools:${NC}     $([ "$INSTALL_CLOUD" = true ] && echo '✓ YES' || echo '✗ No')"
echo -e "  ${BOLD}Deep forensics:${NC}  $([ "$INSTALL_FORENSICS" = true ] && echo '✓ YES' || echo '✗ No')"
echo ""

if [ "$SKIP_CONFIRM" != true ]; then
    read -p "Proceed with installation? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]?$ ]]; then
        log_warn "Installation cancelled by user."
        exit 0
    fi
fi

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Safe apt install — logs failures but continues
apt_install() {
    local pkg="$1"
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        log_info "Already installed: $pkg"
        ((SKIPPED_COUNT++)) || true
        return 0
    fi

    if apt-get install -y "$pkg" >> "$LOGFILE" 2>&1; then
        log_info "Installed: $pkg"
        ((INSTALLED_COUNT++)) || true
    else
        log_warn "Failed to install: $pkg (may not be in repos)"
        FAILED_PACKAGES+=("apt:$pkg")
        ((FAILED_COUNT++)) || true
    fi
}

# Safe pip install
pip_install() {
    local pkg="$1"
    if pip3 install --break-system-packages "$pkg" >> "$LOGFILE" 2>&1; then
        log_info "pip installed: $pkg"
        ((INSTALLED_COUNT++)) || true
    else
        log_warn "pip failed: $pkg"
        FAILED_PACKAGES+=("pip:$pkg")
        ((FAILED_COUNT++)) || true
    fi
}

# Safe go install (runs as real user)
go_install() {
    local pkg="$1"
    local binary_name
    binary_name=$(basename "$pkg" | cut -d@ -f1)

    # Check if already installed
    if command -v "$binary_name" &>/dev/null; then
        log_info "Already installed: $binary_name (Go)"
        ((SKIPPED_COUNT++)) || true
        return 0
    fi

    if sudo -u "$REAL_USER" bash -c "export GOPATH=$REAL_HOME/go; export PATH=\$PATH:/usr/local/go/bin:\$GOPATH/bin; go install $pkg" >> "$LOGFILE" 2>&1; then
        # Symlink to /usr/local/bin so it's globally accessible
        local bin_path="$REAL_HOME/go/bin/$binary_name"
        if [ -f "$bin_path" ]; then
            ln -sf "$bin_path" "/usr/local/bin/$binary_name" 2>/dev/null || true
        fi
        log_info "Go installed: $binary_name"
        ((INSTALLED_COUNT++)) || true
    else
        log_warn "Go install failed: $binary_name"
        FAILED_PACKAGES+=("go:$binary_name")
        ((FAILED_COUNT++)) || true
    fi
}

# Safe gem install
gem_install() {
    local pkg="$1"
    if gem install "$pkg" --no-document >> "$LOGFILE" 2>&1; then
        log_info "gem installed: $pkg"
        ((INSTALLED_COUNT++)) || true
    else
        log_warn "gem failed: $pkg"
        FAILED_PACKAGES+=("gem:$pkg")
        ((FAILED_COUNT++)) || true
    fi
}

# ============================================================================
# PHASE 1: SYSTEM UPDATE & BUILD ESSENTIALS
# ============================================================================
log_section "📦 PHASE 1: System Update & Build Essentials"

export DEBIAN_FRONTEND=noninteractive

log_subsection "Updating package lists..."
apt-get update -y >> "$LOGFILE" 2>&1
log_info "Package lists updated"

log_subsection "Installing build essentials..."
CORE_BUILD_PKGS=(
    build-essential
    gcc
    g++
    make
    cmake
    autoconf
    automake
    libtool
    pkg-config
    curl
    wget
    git
    unzip
    p7zip-full
    jq
    tree
    tmux
    iputils-ping
    net-tools
    dnsutils
    ca-certificates
    gnupg
    lsb-release
    software-properties-common
    apt-transport-https
)

for pkg in "${CORE_BUILD_PKGS[@]}"; do
    apt_install "$pkg"
done

# ============================================================================
# PHASE 2: PYTHON ENVIRONMENT
# ============================================================================
log_section "🐍 PHASE 2: Python Environment"

PYTHON_PKGS=(
    python3
    python3-dev
    python3-pip
    python3-venv
    python3-setuptools
    python3-wheel
    libpython3-dev
    libffi-dev
    libssl-dev
    libxml2-dev
    libxslt1-dev
)

for pkg in "${PYTHON_PKGS[@]}"; do
    apt_install "$pkg"
done

# Upgrade pip
pip3 install --break-system-packages --upgrade pip setuptools wheel >> "$LOGFILE" 2>&1
log_info "pip upgraded to latest"

# Install Python requirements from requirements.txt
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    log_subsection "Installing Python packages from requirements.txt..."
    if pip3 install --break-system-packages --no-cache-dir -r "$SCRIPT_DIR/requirements.txt" >> "$LOGFILE" 2>&1; then
        log_info "All requirements.txt packages installed"
    else
        log_warn "Some requirements.txt packages failed — check log"
        # Try one by one for resilience
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "$line" ]] && continue
            # Extract package name (before any version specifier)
            pkg_name=$(echo "$line" | sed 's/[><=!].*//' | xargs)
            [ -z "$pkg_name" ] && continue
            pip_install "$line"
        done < "$SCRIPT_DIR/requirements.txt"
    fi
else
    log_warn "requirements.txt not found at $SCRIPT_DIR/requirements.txt"
fi

# Additional Python security packages not in requirements.txt
log_subsection "Installing additional Python security packages..."
EXTRA_PIP_PKGS=(
    ROPgadget
    ropper
    capstone
    keystone-engine
    unicorn
    pycryptodome
    scapy
    impacket
    ldap3
    shodan
    censys
    volatility3
    checkov
)

if [ "$INSTALL_MINIMAL" != true ]; then
    for pkg in "${EXTRA_PIP_PKGS[@]}"; do
        pip_install "$pkg"
    done
fi

# ============================================================================
# PHASE 3: CORE SECURITY TOOLS (APT)
# ============================================================================

if [ "$INSTALL_MINIMAL" = true ]; then
    log_section "🔧 PHASE 3: Essential Security Tools (Minimal)"

    MINIMAL_TOOLS=(
        nmap
        sqlmap
        nikto
        gobuster
        dirb
        hydra
        john
        binwalk
        exiftool
        whois
        curl
        wget
        netcat-openbsd
        tcpdump
        tshark
    )

    for pkg in "${MINIMAL_TOOLS[@]}"; do
        apt_install "$pkg"
    done

else
    log_section "🔧 PHASE 3: Security Tools (APT)"

    # ── Network Reconnaissance & Scanning ──
    log_subsection "Network Reconnaissance & Scanning"
    NET_RECON_TOOLS=(
        nmap
        masscan
        netcat-openbsd
        hping3
        arping
        fping
        traceroute
        whois
        dnsutils
        dnsrecon
        dnsenum
        fierce
        theharvester
        responder
        netdiscover
        nbtscan
        onesixtyone
        snmpwalk
    )
    for pkg in "${NET_RECON_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # ── Web Application Security ──
    log_subsection "Web Application Security"
    WEB_TOOLS=(
        gobuster
        dirb
        dirsearch
        nikto
        sqlmap
        wpscan
        whatweb
        wafw00f
        arjun
        commix
        cadaver
        davtest
    )
    for pkg in "${WEB_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # ── Authentication & Password Cracking ──
    log_subsection "Authentication & Password Cracking"
    AUTH_TOOLS=(
        hydra
        john
        hashcat
        medusa
        ncrack
        crunch
        cewl
        hash-identifier
        wordlists
        seclists
    )
    for pkg in "${AUTH_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # ── Binary Analysis & Reverse Engineering ──
    log_subsection "Binary Analysis & Reverse Engineering"
    BINARY_TOOLS=(
        gdb
        gdb-multiarch
        radare2
        binwalk
        upx-ucl
        ltrace
        strace
        binutils
        nasm
        file
        xxd
        hexedit
    )
    for pkg in "${BINARY_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # ── Forensics & Steganography (Core) ──
    log_subsection "Forensics & Steganography (Core)"
    FORENSICS_CORE_TOOLS=(
        exiftool
        foremost
        steghide
        binwalk
        strings
        pdftotext
        poppler-utils
        tcpdump
        tshark
        ssdeep
    )
    for pkg in "${FORENSICS_CORE_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # ── Exploitation Frameworks ──
    log_subsection "Exploitation & Post-Exploitation"
    EXPLOIT_TOOLS=(
        metasploit-framework
        evil-winrm
        smbclient
        smbmap
        enum4linux
        crackmapexec
        bloodhound
        impacket-scripts
    )
    # Only install heavy frameworks if --full
    if [ "$INSTALL_FULL" = true ]; then
        for pkg in "${EXPLOIT_TOOLS[@]}"; do
            apt_install "$pkg"
        done
    else
        # Just the lighter ones for core install
        apt_install "smbclient"
        apt_install "smbmap"
        apt_install "enum4linux"
        apt_install "evil-winrm"
        apt_install "impacket-scripts"
    fi

    # ── OSINT Tools ──
    log_subsection "OSINT & Intelligence"
    OSINT_TOOLS=(
        recon-ng
        maltego
        spiderfoot
        sherlock
        sublist3r
    )
    if [ "$INSTALL_FULL" = true ]; then
        for pkg in "${OSINT_TOOLS[@]}"; do
            apt_install "$pkg"
        done
    else
        apt_install "sherlock"
        apt_install "sublist3r"
    fi

    # ── Wireless (Full only) ──
    if [ "$INSTALL_FULL" = true ]; then
        log_subsection "Wireless Tools"
        WIRELESS_TOOLS=(
            aircrack-ng
            kismet
            wifite
            reaver
            bully
            pixiewps
            hostapd-wpe
        )
        for pkg in "${WIRELESS_TOOLS[@]}"; do
            apt_install "$pkg"
        done
    fi

    # ── Misc Utilities ──
    log_subsection "Miscellaneous Utilities"
    MISC_TOOLS=(
        socat
        proxychains4
        tor
        openvpn
        sshpass
        rlwrap
        pv
        pigz
        dos2unix
        libimage-exiftool-perl
        zbar-tools
    )
    for pkg in "${MISC_TOOLS[@]}"; do
        apt_install "$pkg"
    done
fi

# ============================================================================
# PHASE 4: GO RUNTIME & GO-BASED SECURITY TOOLS
# ============================================================================

if [ "$INSTALL_MINIMAL" != true ]; then

    log_section "🔨 PHASE 4: Go Runtime & Go-based Security Tools"

    # Install Go if not present
    if ! command -v go &>/dev/null; then
        log_subsection "Installing Go runtime..."
        GO_VERSION="1.22.4"
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  GO_ARCH="amd64" ;;
            aarch64) GO_ARCH="arm64" ;;
            armv7l)  GO_ARCH="armv6l" ;;
            *)       GO_ARCH="amd64" ;;
        esac

        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz >> "$LOGFILE" 2>&1
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz >> "$LOGFILE" 2>&1
        rm /tmp/go.tar.gz

        # Set up Go paths
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' > /etc/profile.d/go.sh
        export PATH=$PATH:/usr/local/go/bin:$REAL_HOME/go/bin

        log_info "Go $GO_VERSION installed"
    else
        log_info "Go already installed: $(go version)"
    fi

    # Ensure Go bin directories exist
    sudo -u "$REAL_USER" mkdir -p "$REAL_HOME/go/bin" 2>/dev/null || true

    # Go-based security tools
    log_subsection "Installing Go-based security tools..."

    GO_TOOLS=(
        # Web scanning & fuzzing
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/OJ/gobuster/v3@latest"
        "github.com/evilsocket/legba/cmd/legba@latest"

        # XSS & parameter discovery
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/s0md3v/paramspider@latest"

        # Subdomain & URL discovery
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/tomnomnom/assetfinder@latest"

        # Network
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    )

    if [ "$INSTALL_FULL" = true ]; then
        GO_TOOLS+=(
            "github.com/sensepost/gowitness@latest"
            "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
            "github.com/projectdiscovery/uncover/cmd/uncover@latest"
            "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
            "github.com/jaeles-project/jaeles@latest"
            "github.com/lc/subjs@latest"
            "github.com/tomnomnom/httprobe@latest"
            "github.com/tomnomnom/meg@latest"
            "github.com/tomnomnom/qsreplace@latest"
        )
    fi

    for tool in "${GO_TOOLS[@]}"; do
        go_install "$tool"
    done
fi

# ============================================================================
# PHASE 5: RUBY & GEM-BASED TOOLS
# ============================================================================

if [ "$INSTALL_MINIMAL" != true ]; then

    log_section "💎 PHASE 5: Ruby & Gem-based Tools"

    # Install Ruby if not present
    apt_install "ruby"
    apt_install "ruby-dev"

    GEM_TOOLS=(
        zsteg
        one_gadget
    )

    for gem_pkg in "${GEM_TOOLS[@]}"; do
        gem_install "$gem_pkg"
    done
fi

# ============================================================================
# PHASE 6: BROWSER AUTOMATION (CHROMIUM + CHROMEDRIVER)
# ============================================================================

if [ "$INSTALL_MINIMAL" != true ]; then

    log_section "🌐 PHASE 6: Browser Automation (Selenium)"

    apt_install "chromium"
    apt_install "chromium-driver"

    # Fallback names for different distros
    if ! command -v chromium &>/dev/null && ! command -v chromium-browser &>/dev/null; then
        apt_install "chromium-browser"
        apt_install "chromium-chromedriver"
    fi

    if command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null; then
        log_info "Chromium ready for Selenium browser agent"
    else
        log_warn "Chromium not installed — Selenium browser agent will not work"
    fi
fi

# ============================================================================
# PHASE 7: GDB EXTENSIONS (PEDA, GEF, Pwngdb)
# ============================================================================

if [ "$INSTALL_MINIMAL" != true ]; then

    log_section "🔬 PHASE 7: GDB Extensions"

    GDB_EXT_DIR="$REAL_HOME/.gdb-extensions"
    sudo -u "$REAL_USER" mkdir -p "$GDB_EXT_DIR" 2>/dev/null || true

    # GEF (GDB Enhanced Features)
    if [ ! -f "$GDB_EXT_DIR/gef.py" ]; then
        log_subsection "Installing GEF..."
        if sudo -u "$REAL_USER" wget -q "https://raw.githubusercontent.com/hugsy/gef/main/gef.py" -O "$GDB_EXT_DIR/gef.py" >> "$LOGFILE" 2>&1; then
            log_info "GEF installed"
        else
            log_warn "GEF download failed"
        fi
    else
        log_info "GEF already installed"
    fi

    # PEDA
    if [ ! -d "$GDB_EXT_DIR/peda" ]; then
        log_subsection "Installing PEDA..."
        if sudo -u "$REAL_USER" git clone --depth 1 https://github.com/longld/peda.git "$GDB_EXT_DIR/peda" >> "$LOGFILE" 2>&1; then
            log_info "PEDA installed"
        else
            log_warn "PEDA clone failed"
        fi
    else
        log_info "PEDA already installed"
    fi

    # Pwngdb
    if [ ! -d "$GDB_EXT_DIR/Pwngdb" ]; then
        log_subsection "Installing Pwngdb..."
        if sudo -u "$REAL_USER" git clone --depth 1 https://github.com/scwuaptx/Pwngdb.git "$GDB_EXT_DIR/Pwngdb" >> "$LOGFILE" 2>&1; then
            log_info "Pwngdb installed"
        else
            log_warn "Pwngdb clone failed"
        fi
    else
        log_info "Pwngdb already installed"
    fi

    # Create a switcher script
    cat > /usr/local/bin/gdb-gef << 'GDBEOF'
#!/bin/bash
gdb -ex "source ~/.gdb-extensions/gef.py" "$@"
GDBEOF
    chmod +x /usr/local/bin/gdb-gef

    cat > /usr/local/bin/gdb-peda << 'GDBEOF'
#!/bin/bash
gdb -ex "source ~/.gdb-extensions/peda/peda.py" "$@"
GDBEOF
    chmod +x /usr/local/bin/gdb-peda

    log_info "GDB extension switchers created: gdb-gef, gdb-peda"
fi

# ============================================================================
# PHASE 8: GHIDRA (Headless RE Framework)
# ============================================================================

if [ "$INSTALL_MINIMAL" != true ] && [ "$INSTALL_FULL" = true ]; then

    log_section "👻 PHASE 8: Ghidra (Headless RE)"

    if command -v ghidra &>/dev/null || [ -d "/opt/ghidra" ]; then
        log_info "Ghidra already installed"
    else
        # Try apt first (Kali has it)
        if apt_install "ghidra" 2>/dev/null; then
            log_info "Ghidra installed via apt"
        else
            log_subsection "Installing Ghidra from GitHub releases..."
            # Install Java dependency
            apt_install "default-jdk"

            GHIDRA_VERSION="11.3.1"
            GHIDRA_DATE="20250205"
            GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"

            if wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip >> "$LOGFILE" 2>&1; then
                unzip -q /tmp/ghidra.zip -d /opt/ >> "$LOGFILE" 2>&1
                mv /opt/ghidra_* /opt/ghidra 2>/dev/null || true
                ln -sf /opt/ghidra/ghidraRun /usr/local/bin/ghidra 2>/dev/null || true
                ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless 2>/dev/null || true
                rm -f /tmp/ghidra.zip
                log_info "Ghidra $GHIDRA_VERSION installed to /opt/ghidra"
            else
                log_warn "Ghidra download failed — install manually from https://ghidra-sre.org"
            fi
        fi
    fi
fi

# ============================================================================
# OPTIONAL: CLOUD SECURITY TOOLS
# ============================================================================

if [ "$INSTALL_CLOUD" = true ]; then

    log_section "☁️  OPTIONAL: Cloud & Container Security Tools"

    # Python-based cloud tools
    log_subsection "Python-based cloud tools..."
    CLOUD_PIP_TOOLS=(
        prowler
        scoutsuite
        checkov
    )
    for pkg in "${CLOUD_PIP_TOOLS[@]}"; do
        pip_install "$pkg"
    done

    # Trivy (container scanner)
    log_subsection "Installing Trivy..."
    if ! command -v trivy &>/dev/null; then
        if wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key 2>/dev/null | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null; then
            echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
            apt-get update -y >> "$LOGFILE" 2>&1
            apt_install "trivy"
        else
            log_warn "Trivy repo setup failed — try: pip3 install trivy"
        fi
    else
        log_info "Trivy already installed"
    fi

    # Kubectl
    log_subsection "Installing kubectl..."
    if ! command -v kubectl &>/dev/null; then
        if curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl >> "$LOGFILE" 2>&1; then
            chmod +x /usr/local/bin/kubectl
            log_info "kubectl installed"
        else
            log_warn "kubectl download failed"
        fi
    else
        log_info "kubectl already installed"
    fi

    # kube-bench
    log_subsection "Installing kube-bench..."
    if ! command -v kube-bench &>/dev/null; then
        go_install "github.com/aquasecurity/kube-bench@latest"
    else
        log_info "kube-bench already installed"
    fi

    # kube-hunter
    pip_install "kube-hunter"

    # Terraform (IaC)
    log_subsection "Installing Terraform..."
    if ! command -v terraform &>/dev/null; then
        apt_install "terraform" || {
            # Fallback: HashiCorp repo
            wget -qO- https://apt.releases.hashicorp.com/gpg 2>/dev/null | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg 2>/dev/null
            echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
            apt-get update -y >> "$LOGFILE" 2>&1
            apt_install "terraform"
        }
    else
        log_info "Terraform already installed"
    fi

    # terrascan
    pip_install "terrascan"
fi

# ============================================================================
# OPTIONAL: DEEP FORENSICS TOOLS
# ============================================================================

if [ "$INSTALL_FORENSICS" = true ]; then

    log_section "🔎 OPTIONAL: Deep Forensics & Memory Analysis"

    FORENSICS_DEEP_TOOLS=(
        autopsy
        sleuthkit
        scalpel
        bulk-extractor
        dc3dd
        testdisk
        photorec
        volatility3
        yara
        plaso
        log2timeline
        regripper
    )

    for pkg in "${FORENSICS_DEEP_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # Stego tools
    log_subsection "Steganography tools..."
    STEGO_TOOLS=(
        outguess
        stegsnow
    )
    for pkg in "${STEGO_TOOLS[@]}"; do
        apt_install "$pkg"
    done

    # jsteg (Go-based)
    go_install "github.com/lukechampine/jsteg@latest"

    # Volatility3 via pip (latest)
    pip_install "volatility3"
fi

# ============================================================================
# OPTIONAL: BOAZ EVASION FRAMEWORK
# ============================================================================

if [ "$INSTALL_BOAZ" = true ]; then

    log_section "🛡️  OPTIONAL: BOAZ Evasion Framework Compile Chain"

    log_warn "BOAZ requires heavy compile tools (mingw-w64, wine, LLVM, cmake, ninja)"
    log_warn "This will add ~2-4 GB to your installation"

    BOAZ_PKGS=(
        mingw-w64
        mingw-w64-tools
        gcc-mingw-w64
        g++-mingw-w64
        binutils-mingw-w64
        wine
        wine64
        cmake
        ninja-build
        clang
        nasm
        osslsigncode
        gcc-multilib
        g++-multilib
    )

    for pkg in "${BOAZ_PKGS[@]}"; do
        apt_install "$pkg"
    done

    # Enable 32-bit architecture for Wine
    dpkg --add-architecture i386 >> "$LOGFILE" 2>&1 || true
    apt-get update -y >> "$LOGFILE" 2>&1 || true
    apt_install "wine32:i386" || log_warn "wine32 i386 failed — may not affect functionality"

    # Python deps for BOAZ
    pip_install "pyinstaller"
    pip_install "pyopenssl"
    pip_install "base58"

    # Run BOAZ's own setup if present
    BOAZ_DIR="$SCRIPT_DIR/external_tools/BOAZ_beta"
    if [ -d "$BOAZ_DIR" ] && [ -f "$BOAZ_DIR/requirements.sh" ]; then
        log_subsection "Running BOAZ requirements.sh..."
        log_warn "BOAZ setup is interactive — it may prompt you."
        # Make non-interactive where possible
        cd "$BOAZ_DIR"
        chmod +x requirements.sh
        # Install BOAZ pip deps
        if [ -f "requirements.txt" ]; then
            pip3 install --break-system-packages -r requirements.txt >> "$LOGFILE" 2>&1 || true
        fi
        cd "$SCRIPT_DIR"
        log_info "BOAZ dependencies installed (run external_tools/BOAZ_beta/requirements.sh manually for full LLVM obfuscator setup)"
    else
        log_warn "BOAZ directory not found at $BOAZ_DIR — skipping BOAZ-specific setup"
    fi
fi

# ============================================================================
# PHASE 9: WORDLISTS
# ============================================================================

if [ "$INSTALL_MINIMAL" != true ]; then

    log_section "📖 PHASE 9: Wordlists"

    apt_install "wordlists"
    apt_install "seclists"

    # Ensure rockyou is decompressed
    ROCKYOU="/usr/share/wordlists/rockyou.txt"
    ROCKYOU_GZ="/usr/share/wordlists/rockyou.txt.gz"
    if [ -f "$ROCKYOU_GZ" ] && [ ! -f "$ROCKYOU" ]; then
        log_subsection "Decompressing rockyou.txt..."
        gunzip -k "$ROCKYOU_GZ" 2>/dev/null || gzip -dk "$ROCKYOU_GZ" 2>/dev/null || true
        log_info "rockyou.txt decompressed"
    elif [ -f "$ROCKYOU" ]; then
        log_info "rockyou.txt already available"
    fi
fi

# ============================================================================
# PHASE 10: POST-INSTALL VERIFICATION
# ============================================================================

log_section "✅ PHASE 10: Post-Install Verification"

# Critical tools that MUST be present
CRITICAL_TOOLS=(
    python3
    pip3
    nmap
    curl
    git
)

# Core tools (should be present for standard install)
CORE_VERIFY_TOOLS=(
    nmap
    sqlmap
    nikto
    gobuster
    hydra
    john
    binwalk
    exiftool
    dirb
    whois
)

# Go tools
GO_VERIFY_TOOLS=(
    nuclei
    httpx
    katana
    subfinder
    ffuf
    dalfox
    waybackurls
    gau
)

echo ""
echo -e "${BOLD}  Critical Tools:${NC}"
for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "    ${GREEN}✓${NC} $tool"
    else
        echo -e "    ${RED}✗${NC} $tool ${RED}(MISSING — THIS IS A PROBLEM)${NC}"
    fi
done

if [ "$INSTALL_MINIMAL" != true ]; then
    echo ""
    echo -e "${BOLD}  Core Security Tools:${NC}"
    CORE_OK=0
    CORE_MISSING=0
    for tool in "${CORE_VERIFY_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "    ${GREEN}✓${NC} $tool"
            ((CORE_OK++)) || true
        else
            echo -e "    ${YELLOW}✗${NC} $tool (not found)"
            ((CORE_MISSING++)) || true
        fi
    done

    echo ""
    echo -e "${BOLD}  Go-based Tools:${NC}"
    GO_OK=0
    GO_MISSING=0
    for tool in "${GO_VERIFY_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null || [ -f "$REAL_HOME/go/bin/$tool" ] || [ -f "/usr/local/bin/$tool" ]; then
            echo -e "    ${GREEN}✓${NC} $tool"
            ((GO_OK++)) || true
        else
            echo -e "    ${YELLOW}✗${NC} $tool (not found)"
            ((GO_MISSING++)) || true
        fi
    done
fi

# Python package verification
echo ""
echo -e "${BOLD}  Python Packages:${NC}"
PYTHON_VERIFY=(
    "flask:flask"
    "requests:requests"
    "psutil:psutil"
    "fastmcp:fastmcp"
    "beautifulsoup4:bs4"
    "selenium:selenium"
    "aiohttp:aiohttp"
    "mitmproxy:mitmproxy"
    "pwntools:pwn"
    "angr:angr"
    "cryptography:cryptography"
)
PY_OK=0
PY_MISSING=0
for entry in "${PYTHON_VERIFY[@]}"; do
    IFS=':' read -r name module <<< "$entry"
    if python3 -c "import $module" 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} $name"
        ((PY_OK++)) || true
    else
        echo -e "    ${YELLOW}✗${NC} $name (import failed)"
        ((PY_MISSING++)) || true
    fi
done

# ============================================================================
# SUMMARY
# ============================================================================

log_section "📊 INSTALLATION SUMMARY"

echo -e "  ${GREEN}Installed:${NC}  $INSTALLED_COUNT packages"
echo -e "  ${BLUE}Skipped:${NC}   $SKIPPED_COUNT (already present)"
echo -e "  ${RED}Failed:${NC}    $FAILED_COUNT packages"
echo ""

if [ ${#FAILED_PACKAGES[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Failed packages:${NC}"
    for pkg in "${FAILED_PACKAGES[@]}"; do
        echo -e "    ${RED}•${NC} $pkg"
    done
    echo ""
    echo -e "  ${YELLOW}Tip:${NC} Failed packages may not be available in your repos."
    echo -e "  ${YELLOW}     On non-Kali systems, some tools need manual installation.${NC}"
fi

echo ""
echo -e "  ${BOLD}Log file:${NC} $LOGFILE"
echo ""

# ============================================================================
# FINAL BANNER
# ============================================================================

echo -e "${GREEN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║                                                       ║"
echo "  ║   ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗    ║"
echo "  ║   ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗  ║"
echo "  ║   ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝  ║"
echo "  ║   ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗  ║"
echo "  ║   ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║  ║"
echo "  ║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝  ║"
echo "  ║                                                       ║"
echo "  ║            Setup Complete — v6.0 Ready!               ║"
echo "  ║                                                       ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "    1. ${BOLD}python3 hexstrike_server.py${NC}        — Start the server"
echo -e "    2. ${BOLD}python3 hexstrike_mcp.py${NC}          — Start MCP agent"
echo -e "    3. ${BOLD}docker-compose up -d${NC}              — Or run via Docker"
echo ""
echo -e "  ${YELLOW}Note:${NC} Log out and back in for Go PATH changes to take effect."
echo ""
