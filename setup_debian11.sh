#!/usr/bin/env bash
# ============================================================================
# setup_debian11.sh - Debian 11 eBPF 开发环境一键安装脚本
# 
# 在全新的 Debian 11 (ami-0b1e6494acfc67a42) 上运行:
#   chmod +x setup_debian11.sh && sudo ./setup_debian11.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

# ---------- Pre-checks ----------
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (use sudo)"
fi

ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    err "This script is designed for x86_64, detected: $ARCH"
fi

log "Starting Debian 11 eBPF development environment setup..."
log "Kernel: $(uname -r)"

# ---------- 1. System update ----------
log "Updating package lists..."
apt-get update -qq

log "Upgrading system packages..."
apt-get upgrade -y -qq

# ---------- 2. Essential build tools ----------
log "Installing essential build tools..."
apt-get install -y -qq \
    build-essential \
    make \
    gcc \
    pkg-config \
    curl \
    wget \
    git \
    jq \
    unzip \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# ---------- 3. LLVM / Clang (needed for BPF compilation) ----------
log "Installing clang and LLVM..."
apt-get install -y -qq \
    clang \
    llvm \
    llvm-dev

CLANG_VER=$(clang --version | head -1)
log "Clang installed: $CLANG_VER"

# ---------- 4. eBPF development libraries ----------
log "Installing eBPF/libbpf development packages..."
apt-get install -y -qq \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev

# ---------- 5. Linux headers & BTF ----------
log "Installing kernel headers..."
apt-get install -y -qq \
    "linux-headers-$(uname -r)" || warn "linux-headers not found for $(uname -r), BTF may need manual setup"

# ---------- 6. bpftool ----------
log "Installing bpftool..."
# Try apt first, fall back to manual build
if apt-get install -y -qq bpftool 2>/dev/null; then
    log "bpftool installed via apt"
else
    warn "bpftool not in apt, installing from kernel source..."
    KERNEL_VER=$(uname -r | cut -d'-' -f1)
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    
    # Try to build from linux-tools or download
    if apt-get install -y -qq linux-tools-common "linux-tools-$(uname -r)" 2>/dev/null; then
        log "bpftool installed via linux-tools"
    else
        warn "Could not install bpftool automatically."
        warn "You may need to build it manually from kernel source."
        warn "See: https://github.com/libbpf/bpftool"
    fi
    
    cd /
    rm -rf "$TMPDIR"
fi

# Verify bpftool
if command -v bpftool &>/dev/null; then
    log "bpftool version: $(bpftool version 2>/dev/null | head -1)"
else
    warn "bpftool not found in PATH. Try: apt install linux-tools-\$(uname -r)"
fi

# ---------- 7. Check BTF support ----------
log "Checking BTF (BPF Type Format) support..."
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    log "Kernel BTF available at /sys/kernel/btf/vmlinux"
else
    warn "Kernel BTF not found at /sys/kernel/btf/vmlinux"
    warn "Your kernel may not have CONFIG_DEBUG_INFO_BTF=y"
    warn "eBPF programs using CO-RE may not work without BTF."
    warn "Consider upgrading to a kernel with BTF support (5.4+, compiled with BTF)."
fi

# ---------- 8. Go 1.22 ----------
GO_VERSION="1.22.5"
log "Installing Go ${GO_VERSION}..."

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}')
    log "Go already installed: $CURRENT_GO"
else
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Set up PATH for all users
    cat > /etc/profile.d/go.sh << 'GOEOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
GOEOF
    
    # Also add to current session
    export PATH=$PATH:/usr/local/go/bin
    
    log "Go installed: $(/usr/local/go/bin/go version)"
fi

# ---------- 9. bpf2go tool ----------
log "Installing bpf2go (cilium/ebpf code generator)..."
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

/usr/local/go/bin/go install github.com/cilium/ebpf/cmd/bpf2go@latest 2>/dev/null || \
    warn "bpf2go install deferred - will be fetched during 'go generate'"

# ---------- 10. Debugging tools ----------
log "Installing eBPF debugging/tracing tools..."
apt-get install -y -qq \
    strace \
    perf-tools-unstable 2>/dev/null || true

# bpftrace (if available)
apt-get install -y -qq bpftrace 2>/dev/null || \
    warn "bpftrace not available in apt for this Debian version"

# ---------- Summary ----------
echo ""
echo "================================================================="
echo -e "${GREEN}  eBPF Development Environment Setup Complete!${NC}"
echo "================================================================="
echo ""
echo "  Installed components:"
echo "    - GCC, Make, build-essential"
echo "    - Clang/LLVM (BPF compiler)"
echo "    - libbpf-dev, libelf-dev"
echo "    - Linux headers for $(uname -r)"
echo "    - Go $(GO_VERSION)"
echo "    - bpf2go (cilium/ebpf)"
echo ""

if [[ -f /sys/kernel/btf/vmlinux ]]; then
    echo -e "  BTF status: ${GREEN}Available${NC}"
else
    echo -e "  BTF status: ${RED}Not available${NC} (may need kernel upgrade)"
fi

echo ""
echo "  Next steps:"
echo "    1. source /etc/profile.d/go.sh   # load Go PATH"
echo "    2. cd ebpf-hide-proc"
echo "    3. make deps                      # verify dependencies"
echo "    4. make                            # build the demo"
echo "    5. sudo ./ebpf-hide-proc          # run it!"
echo ""
echo "================================================================="
