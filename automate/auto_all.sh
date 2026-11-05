#!/usr/bin/env bash
# auto_all.sh [target]  —  MASTER dispatcher. Type the target at the prompt (or pass it):
#   a file  (file.pcap / dump.mem / image.png / binary / archive.zip)
#   a URL   (http://x.x.x.x/)
# It detects the kind and runs the right auto_* checker.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"

[ "${1:-}" = "--check" ] && { doctor; exit 0; }
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && {
  echo "usage: auto_all.sh [target] [flag_prefix]"
  echo "       auto_all.sh --check        # dependency doctor"
  echo "  target = file (pcap/mem/evtx/image/binary/dir) or http://host"
  echo "  flag_prefix = e.g. CSG  (restricts flag sweeps to CSG{...}); or env FLAG_PREFIX"
  exit 0; }

if [ -n "${1:-}" ]; then T="$1"; else
  read -rp "[?] target (file.pcap / dump.mem / http://host): " T
fi
[ -n "$T" ] || { echo "nothing given"; exit 1; }
FLAG_PREFIX="${2:-$FLAG_PREFIX}"; set_flag_prefix "$FLAG_PREFIX"; export FLAG_PREFIX FLAG_REGEX

init_report "$T"
evtx_checker(){ if command -v hayabusa >/dev/null 2>&1 || [ -n "${HAYABUSA:-}" ]; then echo auto_hayabusa.sh; else echo auto_winlog.py; fi; }

# --- URL? ---
if printf '%s' "$T" | grep -qiE '^https?://'; then
  echo "[*] URL -> auto_web.py"; run_and_report auto_web.py "$T"

# --- directory: evtx logs -> Hayabusa, otherwise a mixed-file sweep ---
elif [ -d "$T" ]; then
  if find "$T" -iname '*.evtx' -print -quit 2>/dev/null | grep -q .; then
    echo "[*] directory has .evtx -> auto_hayabusa.sh"; run_and_report auto_hayabusa.sh "$T"
  else
    echo "[*] directory (mixed files) -> auto_dirsweep.sh"; run_and_report auto_dirsweep.sh "$T"
  fi

else
  [ -f "$T" ] || { echo "[-] not a URL / file / dir: $T"; exit 1; }
  ext="${T##*.}"; ext="${ext,,}"; desc="$(file -b "$T")"; echo "[*] file: $desc"
  routed=1
  case "$ext" in
    pcap|pcapng|cap)                           run_and_report auto_pcap.sh "$T";;
    mem|raw|vmem|dmp|lime|vmss|vmsn|dump|core) run_and_report auto_mem.sh "$T";;
    evtx)                                      run_and_report "$(evtx_checker)" "$T";;
    png|jpg|jpeg|bmp|gif|wav|mp3|flac|ogg|svg|pdf|docx|doc|xlsx|xls|pptx|ppt)
                                               run_and_report auto_forensic.sh "$T";;
    txt|enc|b64|hex|cipher)                    run_and_report auto_crypto.py "$(cat "$T")";;
    elf|exe|out|axf|o|so)                      run_and_report auto_rev.sh "$T"; run_and_report auto_pwn.sh "$T";;
    zip|rar|7z|tar|gz) echo "[*] archive"; note_report "Archive — \`7z l '$T'\`; if locked: \`zip2john/rar2john → john\`, or \`bkcrack\` for known-plaintext ZipCrypto.";;
    *) routed=0;;
  esac
  if [ "$routed" = 0 ]; then       # extension unknown/misleading -> sniff content
    case "$desc" in
      *pcap*|*"capture file"*|*tcpdump*)   run_and_report auto_pcap.sh "$T";;
      *image*|*PNG*|*JPEG*|*bitmap*|*GIF*) run_and_report auto_forensic.sh "$T";;
      *ELF*|*PE32*|*executable*|*Mach-O*)  echo "[*] binary -> rev + pwn"; run_and_report auto_rev.sh "$T"; run_and_report auto_pwn.sh "$T";;
      *ASCII*|*text*|*Unicode*)            run_and_report auto_crypto.py "$(cat "$T")";;
      *data*)                              echo "[?] raw data — trying memory recon"; run_and_report auto_mem.sh "$T";;
      *)                                   echo "[?] unknown — triage"; run_and_report auto_triage.sh "$T";;
    esac
  fi
fi

finalize_report
