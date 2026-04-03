#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════╗
# ║         DiscoveryKing v2.0 — Installer               ║
# ║         by l33tkid                                   ║
# ╚══════════════════════════════════════════════════════╝
set -e

# ── Colors ────────────────────────────────────────────
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; MAGENTA="\033[95m"; GOLD="\033[38;5;220m"
LIME="\033[38;5;154m"; DIM="\033[2m"; BOLD="\033[1m"; RESET="\033[0m"

info()    { echo -e " ${CYAN}[*]${RESET} $*"; }
ok()      { echo -e " ${GREEN}[+]${RESET} $*"; }
warn()    { echo -e " ${YELLOW}[!]${RESET} $*"; }
error()   { echo -e " ${RED}[-]${RESET} $*"; exit 1; }
section() { echo -e "\n${CYAN}${BOLD}── $* ──${RESET}\n"; }

# ── Banner ────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  ██████╗ ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗   ██╗"
echo "  ██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝"
echo "  ██║  ██║██║███████╗██║     ██║   ██║██║   ██║█████╗  ██████╔╝ ╚████╔╝ "
echo "  ██║  ██║██║╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝  "
echo "  ██████╔╝██║███████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   "
echo "  ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝  "
echo -e "${GOLD}"
echo "                 ██╗  ██╗██╗███╗   ██╗ ██████╗ "
echo "                 ██║ ██╔╝██║████╗  ██║██╔════╝ "
echo "                 █████╔╝ ██║██╔██╗ ██║██║  ███╗"
echo "                 ██╔═██╗ ██║██║╚██╗██║██║   ██║"
echo "                 ██║  ██╗██║██║ ╚████║╚██████╔╝"
echo "                 ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝"
echo -e "${RESET}"
echo -e " ${DIM}Installer  |  by ${LIME}l33tkid${RESET}"
echo ""

# ── OS Detection ──────────────────────────────────────
section "Detecting OS"
OS="$(uname -s 2>/dev/null || echo "Unknown")"
DISTRO=""
PKG_MGR=""

if [[ "$OS" == "Linux" ]]; then
    if   command -v apt-get &>/dev/null; then PKG_MGR="apt";   DISTRO="Debian/Ubuntu"
    elif command -v dnf     &>/dev/null; then PKG_MGR="dnf";   DISTRO="Fedora/RHEL"
    elif command -v yum     &>/dev/null; then PKG_MGR="yum";   DISTRO="CentOS/RHEL"
    elif command -v pacman  &>/dev/null; then PKG_MGR="pacman";DISTRO="Arch Linux"
    elif command -v zypper  &>/dev/null; then PKG_MGR="zypper";DISTRO="openSUSE"
    else warn "Unknown Linux distro — skipping system package install"
    fi
    ok "Linux detected: ${DISTRO:-unknown}"
elif [[ "$OS" == "Darwin" ]]; then
    PKG_MGR="brew"
    ok "macOS detected"
else
    warn "Non-Linux/macOS OS: $OS — skipping system package checks"
fi

# ── Python Check ──────────────────────────────────────
section "Checking Python 3"
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [[ "$MAJOR" -ge 3 && "$MINOR" -ge 7 ]]; then
            PYTHON="$cmd"
            ok "Found: $cmd ($VER) ✓"
            break
        else
            warn "$cmd version $VER is too old (need 3.7+)"
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    warn "Python 3.7+ not found — attempting install..."
    case "$PKG_MGR" in
        apt)    sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip ;;
        dnf)    sudo dnf install -y python3 python3-pip ;;
        yum)    sudo yum install -y python3 python3-pip ;;
        pacman) sudo pacman -Sy --noconfirm python python-pip ;;
        zypper) sudo zypper install -y python3 python3-pip ;;
        brew)   brew install python3 ;;
        *)      error "Cannot install Python automatically. Please install Python 3.7+ manually." ;;
    esac
    PYTHON="python3"
    ok "Python installed"
fi

# ── ping binary check ─────────────────────────────────
section "Checking system ping"
if command -v ping &>/dev/null; then
    ok "ping binary found: $(command -v ping)"
else
    warn "ping not found — attempting install..."
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y iputils-ping ;;
        dnf|yum)sudo dnf install -y iputils ;;
        pacman) sudo pacman -Sy --noconfirm iputils ;;
        zypper) sudo zypper install -y iputils ;;
        brew)   ok "ping is built into macOS" ;;
        *)      warn "Install iputils or inetutils manually for ping support" ;;
    esac
fi

# ── pip check ─────────────────────────────────────────
section "Checking pip"
PIP=""
for cmd in pip3 pip; do
    if command -v "$cmd" &>/dev/null; then
        PIP="$cmd"
        ok "Found: $cmd"
        break
    fi
done

if [[ -z "$PIP" ]]; then
    warn "pip not found — installing..."
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y python3-pip ;;
        dnf|yum)sudo dnf install -y python3-pip ;;
        pacman) sudo pacman -Sy --noconfirm python-pip ;;
        zypper) sudo zypper install -y python3-pip ;;
        brew)   $PYTHON -m ensurepip --upgrade ;;
        *)      $PYTHON -m ensurepip --upgrade || warn "Could not install pip" ;;
    esac
    PIP="pip3"
fi

# ── Optional dependencies ─────────────────────────────
section "Installing optional dependencies"
info "DiscoveryKing uses stdlib only — optional packages extend future features"

OPTIONAL_PKGS=(
    "requests>=2.31.0"
    "dnspython>=2.6.0"
    "colorama>=0.4.6"
)

# Write requirements.txt
cat > requirements.txt << 'EOF'
# DiscoveryKing — optional dependencies
# Core tool uses Python stdlib only; these enable future extensions

requests>=2.31.0      # richer HTTP handling
dnspython>=2.6.0      # advanced DNS resolution
colorama>=0.4.6       # Windows ANSI color support
EOF
ok "requirements.txt written"

read -rp " ${YELLOW}[?]${RESET} Install optional packages now? [y/N]: " INSTALL_OPT
if [[ "${INSTALL_OPT,,}" == "y" ]]; then
    if $PIP install --quiet "${OPTIONAL_PKGS[@]}"; then
        ok "Optional packages installed"
    else
        warn "Some optional packages failed — tool still works without them"
    fi
else
    info "Skipped. Install later with: pip install -r requirements.txt"
fi

# ── Virtual environment (optional) ────────────────────
section "Virtual environment (optional)"
read -rp " ${YELLOW}[?]${RESET} Create a virtual environment? [y/N]: " CREATE_VENV
if [[ "${CREATE_VENV,,}" == "y" ]]; then
    $PYTHON -m venv venv
    ok "venv created — activate with: source venv/bin/activate"
    info "Then run: pip install -r requirements.txt"
fi

# ── Permissions ───────────────────────────────────────
section "Setting permissions"
if [[ -f "discoveryking.py" ]]; then
    chmod +x discoveryking.py
    ok "discoveryking.py marked executable"
else
    warn "discoveryking.py not found in current directory — skipping chmod"
fi

# ── Create launcher alias (optional) ──────────────────
section "Shell alias (optional)"
read -rp " ${YELLOW}[?]${RESET} Add 'discoveryking' alias to your shell? [y/N]: " ADD_ALIAS
if [[ "${ADD_ALIAS,,}" == "y" ]]; then
    TOOL_PATH="$(pwd)/discoveryking.py"
    ALIAS_LINE="alias discoveryking='$PYTHON $TOOL_PATH'"
    SHELL_RC=""

    if [[ -n "$ZSH_VERSION" ]] || [[ "$SHELL" == */zsh ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -n "$BASH_VERSION" ]] || [[ "$SHELL" == */bash ]]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.profile"
    fi

    if grep -q "alias discoveryking=" "$SHELL_RC" 2>/dev/null; then
        warn "Alias already exists in $SHELL_RC — skipping"
    else
        echo "" >> "$SHELL_RC"
        echo "# DiscoveryKing alias" >> "$SHELL_RC"
        echo "$ALIAS_LINE" >> "$SHELL_RC"
        ok "Alias added to $SHELL_RC"
        info "Run: source $SHELL_RC  (or open a new terminal)"
    fi
fi

# ── Done ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   DiscoveryKing installed successfully!   ║${RESET}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════╝${RESET}"
echo ""
echo -e " ${LIME}Quick start:${RESET}"
echo -e "   ${DIM}# Interactive mode${RESET}"
echo -e "   ${CYAN}python3 discoveryking.py${RESET}"
echo ""
echo -e "   ${DIM}# Ping sweep${RESET}"
echo -e "   ${CYAN}python3 discoveryking.py --range 192.168.1.1 192.168.1.254${RESET}"
echo ""
echo -e "   ${DIM}# Probe a target${RESET}"
echo -e "   ${CYAN}python3 discoveryking.py --target example.com${RESET}"
echo ""
echo -e "   ${DIM}# Stealth mode${RESET}"
echo -e "   ${CYAN}python3 discoveryking.py --target example.com --stealth${RESET}"
echo ""
echo -e " ${DIM}See README.md for full usage guide.${RESET}"
echo ""
