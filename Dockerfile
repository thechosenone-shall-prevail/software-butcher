# ============================================================================
# HexStrike AI Red Team Framework v6.0 — Full Docker Image
# ============================================================================
# Base: Kali Linux Rolling (has most security tools in repos)
#
# BUILD:
#   docker build -t hexstrike:latest .
#   docker-compose up -d
#
# USAGE:
#   docker exec -it hexstrike_app bash
#   python3 hexstrike_server.py
# ============================================================================

FROM kalilinux/kali-rolling

# Set non-interactive to prevent prompts during apt-get install
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# ── Stage 1: System update & build essentials ──────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    curl \
    wget \
    git \
    unzip \
    p7zip-full \
    jq \
    tree \
    tmux \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    apt-transport-https \
    dos2unix \
    # Python
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-setuptools \
    python3-wheel \
    libpython3-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 2: Network Reconnaissance & Scanning ────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    netcat-openbsd \
    hping3 \
    fping \
    traceroute \
    whois \
    dnsutils \
    dnsrecon \
    dnsenum \
    fierce \
    theharvester \
    responder \
    netdiscover \
    nbtscan \
    iputils-ping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 3: Web Application Security ─────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    gobuster \
    dirb \
    dirsearch \
    nikto \
    sqlmap \
    wpscan \
    whatweb \
    wafw00f \
    arjun \
    commix \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 4: Authentication & Password Cracking ───────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    hydra \
    john \
    hashcat \
    medusa \
    ncrack \
    crunch \
    cewl \
    hash-identifier \
    wordlists \
    seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Decompress rockyou.txt if compressed
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true; \
    fi

# ── Stage 5: Binary Analysis & Reverse Engineering ────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    gdb-multiarch \
    radare2 \
    binwalk \
    upx-ucl \
    ltrace \
    strace \
    binutils \
    nasm \
    file \
    xxd \
    hexedit \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 6: Forensics & Steganography ────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    exiftool \
    libimage-exiftool-perl \
    foremost \
    steghide \
    outguess \
    tcpdump \
    tshark \
    ssdeep \
    sleuthkit \
    yara \
    pdftotext \
    poppler-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 7: Exploitation & Post-Exploitation ─────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    evil-winrm \
    smbclient \
    smbmap \
    enum4linux \
    impacket-scripts \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 8: OSINT ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    sherlock \
    sublist3r \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 9: Misc Utilities ───────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    proxychains4 \
    sshpass \
    rlwrap \
    pv \
    pigz \
    zbar-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 10: Browser Automation ──────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 11: Ruby & Gem Tools ────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby \
    ruby-dev \
    && gem install zsteg one_gadget --no-document \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 12: Go Runtime & Go-based Security Tools ────────────────────────
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64)  GO_ARCH="amd64" ;; \
        aarch64) GO_ARCH="arm64" ;; \
        *)       GO_ARCH="amd64" ;; \
    esac && \
    wget -q "https://go.dev/dl/go1.22.4.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz && \
    mkdir -p /root/go/bin

# Install Go-based security tools (each as separate RUN for better caching)
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest

RUN go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/tomnomnom/assetfinder@latest

RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# ── Stage 13: GDB Extensions ─────────────────────────────────────────────
RUN mkdir -p /root/.gdb-extensions && \
    wget -q "https://raw.githubusercontent.com/hugsy/gef/main/gef.py" \
        -O /root/.gdb-extensions/gef.py 2>/dev/null || true && \
    git clone --depth 1 https://github.com/longld/peda.git \
        /root/.gdb-extensions/peda 2>/dev/null || true

# ── Stage 14: Python Dependencies ─────────────────────────────────────────
WORKDIR /app

# Copy requirements.txt first (Docker cache optimization)
COPY requirements.txt /app/

# Install Python packages from requirements.txt
RUN pip3 install --ignore-installed --no-cache-dir \
    --break-system-packages \
    -r requirements.txt

# Install additional Python security packages
RUN pip3 install --no-cache-dir --break-system-packages \
    ROPgadget \
    ropper \
    capstone \
    keystone-engine \
    unicorn \
    pycryptodome \
    scapy \
    impacket \
    shodan \
    volatility3 \
    checkov \
    2>/dev/null || true

# ── Healthcheck ───────────────────────────────────────────────────────────
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python3 -c "import flask; import requests; import psutil; print('OK')" || exit 1

# ── Default command ───────────────────────────────────────────────────────
# Keep container running in bash for interactive use
CMD ["/bin/bash"]
