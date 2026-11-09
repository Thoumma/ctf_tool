#!/usr/bin/env bash
# ============================================================================
#  CTF Toolkit Installer  —  for a fresh Kali Linux (2024/2025+)
# ============================================================================
#  Installs every tool referenced in CTF_Techniques_Cheatsheet.html, grouped
#  by category. Safe to re-run (idempotent-ish). Failures are collected and
#  reported at the end instead of aborting the whole run.
#
#  Usage:
#     chmod +x install.sh
#     ./install.sh                 # install everything
#     ./install.sh --core          # apt packages only (fast, no git/pip builds)
#     ./install.sh --category web  # one category: triage|crypto|web|forensics|
#                                   #               stego|rev|pwn|osint|net|misc
#     ./install.sh --list          # list categories and exit
#     ./install.sh --no-sudo       # skip apt (CI / already-root minimal)
#
#  Run as your normal user (it will call sudo when needed), NOT as root,
#  so pipx/gem user installs land in your profile.
# ============================================================================

CATEGORY="all"
USE_SUDO=1
CORE_ONLY=0
FAILED=()

say()  { printf "\n\033[1;36m[*] %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err()  { printf "\033[1;31m[-] %s\033[0m\n" "$*"; FAILED+=("$*"); }

run() { "$@" || err "command failed: $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --category) CATEGORY="$2"; shift 2 ;;
    --core)     CORE_ONLY=1; shift ;;
    --no-sudo)  USE_SUDO=0; shift ;;
    --list)     echo "categories: triage crypto web forensics stego rev pwn osint net misc"; exit 0 ;;
    -h|--help)  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

want() { [ "$CATEGORY" = "all" ] || [ "$CATEGORY" = "$1" ]; }

SUDO=""
if [ "$USE_SUDO" -eq 1 ]; then
  if command -v sudo >/dev/null; then SUDO="sudo"; fi
fi

apt_install() {
  [ "$USE_SUDO" -eq 0 ] && { warn "skipping apt (--no-sudo): $*"; return; }
  $SUDO apt-get install -y --no-install-recommends "$@" && return
  # one unknown package (e.g. Kali-only on Ubuntu) fails the whole batch — retry singly
  warn "apt batch failed — retrying one package at a time"
  for p in "$@"; do
    $SUDO apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1 || err "apt failed: $p"
  done
}

# --break-system-packages only exists on pip >= 23 (older Ubuntu pip rejects it)
pip_install() {
  pip3 install --user --break-system-packages "$@" 2>/dev/null \
    || pip3 install --user "$@" || err "pip failed: $*"
}

pipx_install() {
  command -v pipx >/dev/null || { apt_install pipx; pipx ensurepath >/dev/null 2>&1; }
  pipx install "$1" 2>/dev/null || pipx install --include-deps "$1" || err "pipx failed: $1"
}

gem_install() { command -v gem >/dev/null && { $SUDO gem install "$1" || err "gem failed: $1"; } || err "gem missing for $1"; }

# ---------------------------------------------------------------------------
say "Updating apt index"
if [ "$USE_SUDO" -eq 1 ]; then $SUDO apt-get update || warn "apt update failed (continuing)"; fi

say "Base build/runtime deps"
apt_install git curl wget build-essential cmake python3 python3-pip pipx ruby ruby-dev \
            default-jdk unzip p7zip-full xxd jq ripgrep coreutils \
            python3-dev libssl-dev libffi-dev libgmp-dev libmpfr-dev libmpc-dev

# ============================ PYTHON LIBS (always) =========================
# Imported directly by the cheat-sheet snippets and auto_* scripts.
say "Python CTF libraries (always installed)"
pip_install pwntools pycryptodome z3-solver unicorn capstone sympy gmpy2 \
            ropper beautifulsoup4 impacket requests

# ============================ WORDLISTS & CRACKERS (always) ================
# Installed on every run (not gated by --category) so rockyou/hashcat/SecLists
# are guaranteed present — the auto_* scripts default to these paths.
say "Wordlists & crackers (always installed)"
apt_install hashcat hashcat-utils john john-data hydra ncrack \
            crunch cewl fcrackzip pdfcrack
# dirb ships common.txt on Ubuntu too; wordlists/seclists are Kali-only, so they're
# tried quietly and SecLists is cloned from GitHub when the package is missing
apt_install dirb
$SUDO apt-get install -y --no-install-recommends wordlists seclists >/dev/null 2>&1 || true
if [ ! -d /usr/share/seclists ]; then
  warn "seclists package unavailable — cloning SecLists (large, ~1 GB)"
  $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists \
    || err "SecLists clone failed"
fi
[ -d /usr/share/seclists ] && ok "SecLists: /usr/share/seclists" || warn "SecLists missing"
# unzip rockyou wherever Kali/SecLists shipped it
$SUDO mkdir -p /usr/share/wordlists
[ -f /usr/share/wordlists/rockyou.txt.gz ] && $SUDO gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
rk=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
[ -f "$rk" ] && $SUDO tar -xf "$rk" -C "$(dirname "$rk")" 2>/dev/null

# Wordlist list — "name|candidate source paths…". Each ends up at /usr/share/wordlists/<name>
# (symlinked from the first source that exists), which is where automate/config.sh looks.
WORDLISTS=(
  "rockyou.txt|/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
  "common.txt|/usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/dirb/wordlists/common.txt /usr/share/wordlists/dirb/common.txt"
)
for entry in "${WORDLISTS[@]}"; do
  name=${entry%%|*}; dst=/usr/share/wordlists/$name
  if [ ! -f "$dst" ]; then
    for src in ${entry#*|}; do
      [ -f "$src" ] && { $SUDO ln -sf "$src" "$dst"; break; }
    done
  fi
  [ -f "$dst" ] && ok "$name ready: $dst" || warn "$name not found — set it in automate/config.sh"
done

# ============================== TRIAGE ====================================
if want triage; then
  say "Triage / file analysis"
  apt_install file binwalk foremost scalpel testdisk
  pipx_install binwalk   # newer v3 cli (optional, apt one is fine too)
fi

# ============================== CRYPTO ====================================
if want crypto; then
  say "Crypto"
  apt_install python3-pycryptodome sagemath yafu
  pipx_install name-that-hash
  pipx_install featherduster 2>/dev/null || true
  # RsaCtfTool (the RSA swiss-army knife)
  if [ ! -d "$HOME/tools/RsaCtfTool" ]; then
    mkdir -p "$HOME/tools"
    run git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool "$HOME/tools/RsaCtfTool"
    pip3 install --user --break-system-packages -r "$HOME/tools/RsaCtfTool/requirements.txt" 2>/dev/null \
      || warn "install RsaCtfTool reqs manually"
  fi
  ok "ciphey/ciphers: use dcode.fr + CyberChef (download offline html) for classic ciphers"
fi

# ============================== WEB =======================================
if want web; then
  say "Web"
  apt_install sqlmap ffuf gobuster feroxbuster wfuzz nikto whatweb
  pipx_install jwt_tool 2>/dev/null || run git clone --depth 1 https://github.com/ticarpi/jwt_tool "$HOME/tools/jwt_tool"
  ok "Burp Suite ships with Kali (run 'burpsuite'). SecLists -> /usr/share/seclists"
fi

# ============================== FORENSICS =================================
if want forensics; then
  say "Forensics — disk / memory / artifacts"
  apt_install sleuthkit autopsy ddrescue extundelete ext4magic \
              libguestfs-tools exiftool qpdf poppler-utils \
              bulk-extractor ewf-tools afflib-tools
  # Windows registry / evtx / MFT
  pipx_install regipy
  pipx_install python-registry 2>/dev/null || pip_install python-registry
  pipx_install evtx 2>/dev/null || true                      # evtx_dump binary
  pip_install python-evtx                                    # Evtx lib for auto_winlog.py
  pipx_install analyzeMFT 2>/dev/null || true
  # DeepBlueCLI (event-log threat hunt) — auto_winlog.py mirrors its rules
  [ ! -d "$HOME/tools/DeepBlueCLI" ] && git clone --depth 1 https://github.com/sans-blue-team/DeepBlueCLI "$HOME/tools/DeepBlueCLI" 2>/dev/null
  # Hayabusa (Sigma EVTX timeline) — auto_hayabusa.sh drives this
  if ! command -v hayabusa >/dev/null 2>&1; then
    mkdir -p "$HOME/tools/hayabusa" "$HOME/.local/bin"
    url=$(curl -s https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest \
          | grep -oE 'https://[^"]*lin-x64-gnu\.zip' | head -1)
    if [ -n "$url" ]; then
      wget -q "$url" -O /tmp/hb.zip && unzip -o -q /tmp/hb.zip -d "$HOME/tools/hayabusa" \
        && chmod +x "$HOME/tools/hayabusa"/hayabusa-* 2>/dev/null \
        && ln -sf "$HOME/tools/hayabusa"/hayabusa-*-lin-x64-gnu "$HOME/.local/bin/hayabusa" \
        && ( cd "$HOME/tools/hayabusa" && ./hayabusa-*-lin-x64-gnu update-rules ) >/dev/null 2>&1 \
        && ok "hayabusa + sigma rules -> ~/tools/hayabusa" || err "hayabusa install"
    else err "hayabusa release URL (install manually: Yamato-Security/hayabusa/releases)"; fi
  fi
  command -v chainsaw >/dev/null || ok "chainsaw (sigma hunting): grab the release from github.com/WithSecureLabs/chainsaw"
  # Memory
  pipx_install volatility3
  warn "Volatility2 (legacy profiles) must be installed separately in a py2 venv if needed"
  ok "RegRipper: apt-get install regripper   |   Eric Zimmerman tools are Windows-only (MFTECmd)"
fi

# ============================== STEGO =====================================
if want stego; then
  say "Steganography"
  apt_install steghide outguess stegsnow pngcheck imagemagick sox zbar-tools \
              libimage-exiftool-perl
  gem_install zsteg
  # stegseek (fast steghide cracker) — .deb release
  if ! command -v stegseek >/dev/null; then
    wget -q https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -O /tmp/stegseek.deb \
      && $SUDO apt-get install -y /tmp/stegseek.deb || err "stegseek install"
  fi
  # stegsolve.jar (GUI bit-plane viewer)
  if [ ! -f "$HOME/tools/stegsolve.jar" ]; then
    mkdir -p "$HOME/tools"
    wget -q http://www.caesum.com/handbook/Stegsolve.jar -O "$HOME/tools/stegsolve.jar" \
      && ok "stegsolve -> java -jar ~/tools/stegsolve.jar" || warn "download stegsolve manually"
  fi
  pipx_install stegoveritas 2>/dev/null && stegoveritas_install_deps 2>/dev/null || true
fi

# ============================== REVERSING =================================
if want rev; then
  say "Reverse engineering"
  apt_install radare2 gdb ltrace strace nasm patchelf upx-ucl \
              apktool dex2jar jadx openjdk-17-jre
  # angr + z3 for symbolic solving
  pipx_install angr 2>/dev/null || pip_install angr
  # Ghidra
  if [ ! -d /opt/ghidra ] && [ ! -d "$HOME/tools/ghidra" ]; then
    warn "Ghidra: 'sudo apt-get install -y ghidra' on Kali, or grab the release zip from github.com/NationalSecurityAgency/ghidra"
    apt_install ghidra 2>/dev/null || true
  fi
  # pwndbg (nicer gdb)
  if [ ! -d "$HOME/tools/pwndbg" ]; then
    run git clone --depth 1 https://github.com/pwndbg/pwndbg "$HOME/tools/pwndbg"
    ( cd "$HOME/tools/pwndbg" && ./setup.sh ) || warn "run pwndbg setup.sh manually"
  fi
fi

# ============================== PWN =======================================
if want pwn; then
  say "Pwn / binary exploitation"
  apt_install gdb gcc-multilib libc6-dbg checksec socat netcat-openbsd
  pipx_install ROPgadget
  gem_install one_gadget
  ok "glibc version DBs: use 'libc.rip' or local libc-database for ret2libc"
fi

# ============================== NETWORK ===================================
if want net; then
  say "Network / PCAP"
  apt_install wireshark tshark tcpdump tcpflow ngrep zeek \
              python3-scapy dsniff net-tools dnsutils
  pipx_install pyshark 2>/dev/null || true
  # USB HID keystroke extraction helper (very common CTF)
  [ ! -f "$HOME/tools/ctf-usb-keyboard-parser" ] && \
    git clone --depth 1 https://github.com/TeamRocketIst/ctf-usb-keyboard-parser "$HOME/tools/ctf-usb-keyboard-parser" 2>/dev/null
  ok "Let non-root capture: sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark \$USER"
fi

# ============================== OSINT =====================================
if want osint; then
  say "OSINT"
  apt_install exiftool whois dnsrecon
  pipx_install sherlock-project 2>/dev/null || pipx_install sherlock 2>/dev/null || \
    run git clone --depth 1 https://github.com/sherlock-project/sherlock "$HOME/tools/sherlock"
  pipx_install holehe 2>/dev/null || true
  pipx_install maigret 2>/dev/null || true
  ok "crt.sh, web.archive.org, Google/Yandex Lens, WhatsMyName are web-based"
fi

# ============================== MISC ======================================
if want misc; then
  say "Misc / archives / jail"
  apt_install john hashcat fcrackzip pdfcrack hashcat-utils \
              zbar-tools qrencode
  # bkcrack (known-plaintext ZipCrypto)
  if [ ! -x "$HOME/tools/bkcrack/bkcrack" ]; then
    run git clone --depth 1 https://github.com/kimci86/bkcrack "$HOME/tools/bkcrack"
    ( cd "$HOME/tools/bkcrack" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j ) \
      && cp "$HOME/tools/bkcrack/build/bkcrack" "$HOME/tools/bkcrack/" 2>/dev/null \
      || warn "build bkcrack manually"
  fi
  # *2john helpers live in /usr/share/john/ on Kali
  ok "*2john converters: ls /usr/share/john/*2john*"
fi

# ---------------------------------------------------------------------------
say "Done."
echo "Add these to your shell rc if not already present:"
echo '   export PATH="$HOME/.local/bin:$HOME/tools:$PATH"'
echo "   alias stegsolve='java -jar ~/tools/stegsolve.jar'"
echo "   alias rsactftool='python3 ~/tools/RsaCtfTool/RsaCtfTool.py'"

if [ "${#FAILED[@]}" -gt 0 ]; then
  warn "Some items failed — install these manually:"
  for f in "${FAILED[@]}"; do echo "     - $f"; done
  exit 1
else
  ok "All requested tools installed cleanly."
fi
