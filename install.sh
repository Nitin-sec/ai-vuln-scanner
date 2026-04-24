#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ThreatMap Infra — One-Command Setup
# Usage:  bash install.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; W='\033[1;37m'; D='\033[2m'; N='\033[0m'

ok()  { printf "${G}  [✔]${N}  %s\n" "$1"; }
err() { printf "${R}  [✗]${N}  %s\n" "$1"; }
inf() { printf "${B}  [*]${N}  %s\n" "$1"; }
wrn() { printf "${Y}  [!]${N}  %s\n" "$1"; }
hdr() { printf "\n${W}  %s${N}\n  %s\n" "$1" "$(printf '─%.0s' {1..50})"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─────────────────────────────────────────────────────────────
echo "
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███╗   ███╗ █████╗ ██████╗
     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██╔████╔██║███████║██████╔╝
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
"
echo "  THREATMAP — Setup & Dependency Installer"
echo ""

# ── OS check ─────────────────────────────────────────────────
hdr "Environment Check"
if ! command -v apt-get &>/dev/null; then
    err "Requires a Debian/Ubuntu/Kali system. Exiting."
    exit 1
fi
ok "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
ok "User: $(whoami)"

# ── System packages ───────────────────────────────────────────
hdr "System Packages"
inf "Updating package list..."
sudo apt-get update -qq 2>/dev/null

PKGS=(nmap nikto gobuster sslscan whatweb whois dnsutils curl python3 python3-venv python3-pip)
MISSING=()
for p in "${PKGS[@]}"; do
    dpkg -l "$p" &>/dev/null || MISSING+=("$p")
done

if [ ${#MISSING[@]} -gt 0 ]; then
    inf "Installing: ${MISSING[*]}"
    sudo apt-get install -y -qq "${MISSING[@]}" 2>/dev/null && ok "System packages ready"
else
    ok "All system packages already installed"
fi

# Optional: seclists wordlists
if ! dpkg -l seclists &>/dev/null; then
    wrn "seclists not installed (needed for gobuster directory scanning)"
    wrn "Install with: sudo apt install seclists"
    wrn "Skipping for now — gobuster will still work with built-in wordlists"
fi

# ── Go ────────────────────────────────────────────────────────
hdr "Go Language Runtime"
if ! command -v go &>/dev/null; then
    inf "Go not found. Installing via apt..."
    sudo apt-get install -y -qq golang-go 2>/dev/null
fi

GO_VERSION=$(go version 2>/dev/null | awk '{print $3}' || echo "unknown")
ok "Go: $GO_VERSION"

# Ensure Go bin in PATH
GOPATH_BIN="$(go env GOPATH 2>/dev/null)/bin"
export PATH="$PATH:$GOPATH_BIN"

if ! grep -q 'GOPATH' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> "$HOME/.bashrc"
    inf "Added Go bin to ~/.bashrc (run: source ~/.bashrc)"
fi

# ── Go tools ─────────────────────────────────────────────────
hdr "Go Security Tools"

install_go_tool() {
    local name="$1" pkg="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name — already installed"
    else
        inf "Installing $name..."
        if go install "$pkg" 2>/dev/null; then
            ok "$name — installed"
        else
            wrn "$name — install failed (non-critical, tool will be skipped during scans)"
        fi
    fi
}

install_go_tool subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool assetfinder "github.com/tomnomnom/assetfinder@latest"
install_go_tool nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# Update nuclei templates if nuclei installed
if command -v nuclei &>/dev/null; then
    inf "Updating Nuclei templates (this may take a moment)..."
    nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated" || wrn "Nuclei template update failed — will retry on first scan"
fi

# ── Python environment ────────────────────────────────────────
hdr "Python Environment"
VENV_DIR="$SCRIPT_DIR/venv"
VENV_PY="$VENV_DIR/bin/python"

if [ ! -f "$VENV_PY" ]; then
    inf "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created"
fi

inf "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip 2>/dev/null
"$VENV_DIR/bin/pip" install --quiet -r requirements.txt 2>/dev/null
"$VENV_DIR/bin/pip" install --quiet questionary 2>/dev/null || true
"$VENV_DIR/bin/pip" install --quiet llama-cpp-python 2>/dev/null || true
ok "Python packages installed"

# ── Permissions ─────────────────────────────────────────────
hdr "Permissions"
chmod +x run.sh 2>/dev/null && ok "run.sh is executable"
chmod +x threatmap 2>/dev/null && ok "threatmap runner is executable"

# ── Verification ─────────────────────────────────────────────
hdr "Tool Verification"

printf "  %-18s %-10s %s\n" "Tool" "Status" "Path"
printf "  %-18s %-10s %s\n" "────────────────" "────────" "──────────────────"

check_tool() {
    local name="$1" required="$2"
    if command -v "$name" &>/dev/null; then
        printf "  ${G}%-18s ✔${N}         %s\n" "$name" "$(command -v $name)"
    elif [ "$required" = "required" ]; then
        printf "  ${R}%-18s ✗${N}         not found\n" "$name"
    else
        printf "  ${Y}%-18s ○${N}         optional — not installed\n" "$name"
    fi
}

check_tool nmap       required
check_tool nikto      required
check_tool gobuster   required
check_tool sslscan    required
check_tool whatweb    required
check_tool curl       required
check_tool subfinder  optional
check_tool httpx      optional
check_tool assetfinder optional
check_tool nuclei     optional

# ── Summary ───────────────────────────────────────────────────
printf "\n  $(printf '─%.0s' {1..50})\n"
printf "\n"
ok "Setup complete."
printf "\n  ${W}To run ThreatMap:${N}\n"
printf "  ${D}$ ${N}${W}./threatmap${N}\n\n"
printf "  ${D}Reports will be saved to: ~/ThreatMap-Reports/${N}\n\n"
