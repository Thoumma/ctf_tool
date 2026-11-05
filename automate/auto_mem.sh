#!/usr/bin/env bash
# auto_mem.sh [dump] [flag_prefix]  —  Volatility 3 recon (per-plugin logs) + flag sweep.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then SRC="$1"; else read -rp "[?] memory dump: " SRC; fi
[ -n "$SRC" ] || { echo "no dump given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
F="$(readlink -f "$SRC")"; OUT="mem_$(basename "$F")_out"; mkdir -p "$OUT"; cd "$OUT" || exit 1

[ -z "$VOL" ] && VOL="$(command -v vol || command -v vol.py || command -v volatility3 || true)"
[ -z "$VOL" ] && { echo "[-] volatility3 not found -> pipx install volatility3"; exit 1; }
MEMTO=$((TOOL_TIMEOUT * 4))        # memory plugins are slow
mrun(){ local log="$1"; shift; cyn "$*"
  if have timeout && [ "$TOOL_TIMEOUT" -gt 0 ]; then timeout "$MEMTO" "$@" 2>/dev/null | tee "$log" | head -n "$HEAD_LINES"
  else "$@" 2>/dev/null | tee "$log" | head -n "$HEAD_LINES"; fi; }

OS=windows
"$VOL" -f "$F" windows.info >/dev/null 2>&1 || { "$VOL" -f "$F" banners.Banners >/dev/null 2>&1 && OS=linux; }
grn "[*] detected OS = $OS"
if [ "$OS" = windows ]; then
  for p in windows.info windows.pstree windows.cmdline windows.netscan \
           windows.hashdump windows.malfind windows.cmdscan windows.consoles; do
    mrun "${p}.log" "$VOL" -f "$F" "$p"
  done
  "$VOL" -f "$F" windows.filescan 2>/dev/null > filescan.txt
  cyn "filescan hits"; grep -iE 'flag|secret|desktop|\.txt|\.zip|\.docx?' filescan.txt | head -40
  grn "[*] dump a file: $VOL -f '$F' windows.dumpfiles --virtaddr 0xADDR"
else
  for p in banners.Banners linux.pslist linux.pstree linux.bash linux.lsof; do mrun "${p}.log" "$VOL" -f "$F" "$p"; done
fi

cyn "strings flag sweep"
strings -n 8 "$F" | grep -aoE "$FLAG_REGEX" | sort -u | head -40
