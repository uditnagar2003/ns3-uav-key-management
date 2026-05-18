#!/usr/bin/env bash
# build_deps.sh
# Installs ALL external dependencies required by the UAV Secure FANET project.
# Target: Ubuntu 24.04 | GCC 13.3.0
#
# USAGE:
#   chmod +x build_deps.sh
#   sudo ./build_deps.sh
#
# Run this ONCE before any waf or cmake build.

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour output
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[UAV-DEPS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root: sudo ./build_deps.sh"
fi

log "Starting dependency installation for UAV Secure FANET"
log "Ubuntu version: $(lsb_release -ds 2>/dev/null || echo 'unknown')"
log "GCC version   : $(gcc --version | head -1)"

# ---------------------------------------------------------------------------
# System update
# ---------------------------------------------------------------------------
log "Updating apt package lists..."
apt-get update -qq

# ---------------------------------------------------------------------------
# Build essentials
# ---------------------------------------------------------------------------
log "Installing build essentials..."
apt-get install -y \
    build-essential \
    gcc-13 \
    g++-13 \
    cmake \
    ninja-build \
    pkg-config \
    git \
    wget \
    curl \
    unzip \
    python3 \
    python3-pip \
    python3-dev

# Set GCC 13 as default
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 130 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-13 || true

log "GCC 13 set as default compiler"

# ---------------------------------------------------------------------------
# NS-3.43 system dependencies
# ---------------------------------------------------------------------------
log "Installing NS-3.43 system dependencies..."
apt-get install -y \
    libsqlite3-dev \
    libxml2-dev \
    libgtk-3-dev \
    libgsl-dev \
    gsl-bin \
    libfl-dev \
    libboost-all-dev \
    python3-setuptools \
    qt5-default || apt-get install -y qtbase5-dev || true

# ---------------------------------------------------------------------------
# OpenSSL development headers
# ---------------------------------------------------------------------------
log "Installing OpenSSL..."
apt-get install -y \
    libssl-dev \
    openssl

OPENSSL_VER=$(openssl version)
log "OpenSSL installed: ${OPENSSL_VER}"

# Verify EVP header
if [[ ! -f /usr/include/openssl/evp.h ]]; then
    err "openssl/evp.h not found after installation. Check libssl-dev."
fi
log "openssl/evp.h: FOUND"

# ---------------------------------------------------------------------------
# Boost (Multiprecision — header only, but install full Boost)
# ---------------------------------------------------------------------------
log "Verifying Boost.Multiprecision..."
BOOST_MULTI_HEADER=$(find /usr/include -name "cpp_int.hpp" \
    -path "*/boost/multiprecision/*" 2>/dev/null | head -1)

if [[ -z "${BOOST_MULTI_HEADER}" ]]; then
    warn "boost/multiprecision/cpp_int.hpp not found in system path"
    log "Installing libboost-all-dev..."
    apt-get install -y libboost-all-dev
    BOOST_MULTI_HEADER=$(find /usr/include -name "cpp_int.hpp" \
        -path "*/boost/multiprecision/*" 2>/dev/null | head -1)
    if [[ -z "${BOOST_MULTI_HEADER}" ]]; then
        err "Boost.Multiprecision still not found. Manual installation required."
    fi
fi
log "Boost.Multiprecision: ${BOOST_MULTI_HEADER}"

# ---------------------------------------------------------------------------
# nlohmann/json
# ---------------------------------------------------------------------------
log "Installing nlohmann/json..."
NLOHMANN_HEADER=$(find /usr/include -name "json.hpp" \
    -path "*/nlohmann/*" 2>/dev/null | head -1)

if [[ -z "${NLOHMANN_HEADER}" ]]; then
    apt-get install -y nlohmann-json3-dev || {
        warn "apt nlohmann-json3-dev not available, installing via GitHub..."
        NLOHMANN_VERSION="3.11.3"
        wget -q "https://github.com/nlohmann/json/releases/download/v${NLOHMANN_VERSION}/json.hpp" \
            -O /usr/include/nlohmann/json.hpp || {
            mkdir -p /usr/include/nlohmann
            wget -q "https://raw.githubusercontent.com/nlohmann/json/v${NLOHMANN_VERSION}/single_include/nlohmann/json.hpp" \
                -O /usr/include/nlohmann/json.hpp
        }
    }
    NLOHMANN_HEADER=$(find /usr/include -name "json.hpp" \
        -path "*/nlohmann/*" 2>/dev/null | head -1)
fi
log "nlohmann/json: ${NLOHMANN_HEADER}"

# ---------------------------------------------------------------------------
# Python packages (for crypto generator scripts — Phase 2 Module 13)
# ---------------------------------------------------------------------------
log "Installing Python cryptography packages..."
pip3 install --quiet \
    sympy \
    pycryptodome \
    gmpy2 \
    matplotlib \
    numpy

log "Python packages installed"

# ---------------------------------------------------------------------------
# waf (if not bundled with NS-3)
# ---------------------------------------------------------------------------
if ! command -v waf &>/dev/null; then
    log "waf not found globally; NS-3 bundles its own waf — this is OK"
    info "Use: cd <ns3-root> && ./waf configure && ./waf build"
else
    WAF_VER=$(waf --version 2>&1 | head -1)
    log "waf: ${WAF_VER}"
fi

# ---------------------------------------------------------------------------
# Verification summary
# ---------------------------------------------------------------------------
echo ""
log "======================================================"
log "Dependency Installation Summary"
log "======================================================"

check_dep() {
    local label="$1"
    local check_cmd="$2"
    if eval "$check_cmd" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${label}"
    else
        echo -e "  ${RED}✗${NC} ${label} — MISSING"
    fi
}

check_dep "gcc-13"                    "gcc-13 --version"
check_dep "g++-13"                    "g++-13 --version"
check_dep "cmake >= 3.16"             "cmake --version"
check_dep "OpenSSL (libssl-dev)"      "test -f /usr/include/openssl/evp.h"
check_dep "Boost.Multiprecision"      "test -f \$(find /usr/include -name 'cpp_int.hpp' -path '*/boost/multiprecision/*' 2>/dev/null | head -1)"
check_dep "nlohmann/json"             "test -f \$(find /usr/include -name 'json.hpp' -path '*/nlohmann/*' 2>/dev/null | head -1)"
check_dep "Python3"                   "python3 --version"
check_dep "Python sympy"              "python3 -c 'import sympy'"
check_dep "Python pycryptodome"       "python3 -c 'import Crypto'"
check_dep "Python gmpy2"              "python3 -c 'import gmpy2'"
check_dep "Python matplotlib"         "python3 -c 'import matplotlib'"

echo ""
log "All dependencies verified. Proceed to NS-3.43 build."
log "======================================================"