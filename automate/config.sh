#!/usr/bin/env bash
# config.sh — shared settings + helpers for every auto_* script. EDIT VALUES HERE.
# Sourced by the bash scripts; the Python scripts read the same values from the environment
# (config exports FLAG_REGEX / FLAG_PREFIX / thresholds). Override any value inline, e.g.:
#     FLAG_PREFIX=CSG ./auto_forensic.sh chall.png
#     WORDLIST=~/lists/custom.txt ./auto_all.sh

# ---------- shell hardening (#6) ----------
# Callers already 'set -u'. Add pipefail so a failure mid-pipeline is visible.
# 'set -e' is intentionally NOT used: these are best-effort multi-tool runs where one tool
# failing (or grep matching nothing) is expected and must never abort the whole sweep.
set -o pipefail 2>/dev/null || true

# ---------- flag matching ----------
: "${FLAG_PREFIX:=}"                                   # e.g. CSG  -> matches CSG{...} only
                                                       # multi-event: 'pwnsec|psctf|ctf' (alternation OK)
[ -z "${FLAG_REGEX:-}" ] && FLAG_REGEX='[A-Za-z0-9_]{2,}\{[^}]{1,120}\}'   # generic default
# wrap the prefix in a group so an alternation like pwnsec|psctf|ctf binds correctly
set_flag_prefix(){ [ -n "${1:-}" ] && FLAG_REGEX="(${1})\\{[^}]{1,120}\\}"; }
[ -n "$FLAG_PREFIX" ] && set_flag_prefix "$FLAG_PREFIX"

# ---------- wordlists / tool locations ----------
: "${WORDLIST:=/usr/share/wordlists/rockyou.txt}"      # primary cracking list
: "${SECLISTS:=/usr/share/seclists}"                   # SecLists root
: "${DIRLIST:=/usr/share/wordlists/common.txt}"        # dirbust list (gobuster/ffuf)
: "${HAYABUSA:=}"                                      # hayabusa binary (auto-detected if empty)
: "${VOL:=}"                                           # volatility3 cmd (auto-detected if empty)

# ---------- limits ----------
: "${TOOL_TIMEOUT:=120}"                               # seconds per external tool (0 = no limit)
: "${HEAD_LINES:=80}"                                  # console preview lines (FULL output still saved)

# ---------- auto_web rate-limit safety ----------
: "${WEB_DELAY:=0.4}"                                  # min seconds between HTTP requests
: "${WEB_MAX_RETRIES:=4}"                              # retries on HTTP 429/503 (exp backoff + Retry-After)
: "${WEB_BUDGET:=400}"                                 # hard cap on total requests per run

# ---------- auto_winlog thresholds ----------
: "${FAIL_THRESHOLD:=10}"                              # 4625 fails/account -> bruteforce
: "${SPRAY_THRESHOLD:=5}"                              # 4648 distinct targets -> password spray
: "${ADMIN_THRESHOLD:=5}"                              # 4672 admin logons/account

export FLAG_REGEX FLAG_PREFIX WORDLIST SECLISTS DIRLIST HAYABUSA VOL \
       TOOL_TIMEOUT HEAD_LINES FAIL_THRESHOLD SPRAY_THRESHOLD ADMIN_THRESHOLD \
       WEB_DELAY WEB_MAX_RETRIES WEB_BUDGET

# ---------- helpers ----------
have(){ command -v "$1" >/dev/null 2>&1; }
cyn(){ printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
grn(){ printf '\033[1;32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[1;33m%s\033[0m\n' "$*"; }

# runlog <logfile> <cmd...> : run with a timeout, tee FULL output to logfile, show a preview.
runlog(){
  local log="$1"; shift; cyn "$*"
  if have timeout && [ "$TOOL_TIMEOUT" -gt 0 ]; then
    timeout "$TOOL_TIMEOUT" "$@" 2>&1 | tee "$log" | head -n "$HEAD_LINES"
  else
    "$@" 2>&1 | tee "$log" | head -n "$HEAD_LINES"
  fi
  local n; n="$(wc -l < "$log" 2>/dev/null || echo 0)"
  [ "$n" -gt "$HEAD_LINES" ] && ylw "   (+$((n-HEAD_LINES)) more lines saved in $log)"
  return 0
}

# flagsweep <path> : recursive, deduped flag grep over a dir/file.
flagsweep(){ cyn "FLAG SWEEP ($1)"; grep -raoE "$FLAG_REGEX" "$1" 2>/dev/null | sort -u; return 0; }

# strip ANSI colour codes from a stream
_noansi(){ sed -r 's/\x1b\[[0-9;]*m//g'; }

# -------- aggregated report (used by auto_all.sh) --------
REPORT=""; REPORTDIR=""; REPORT_TGT=""
init_report(){
  REPORT_TGT="$1"
  local base; base="$(basename "$1")"; base="$(printf '%s' "$base" | tr -c 'A-Za-z0-9._-' '_')"
  REPORTDIR="report_${base}"; mkdir -p "$REPORTDIR"; REPORT="$REPORTDIR/report.md"
  {
    echo "# CTF auto-check report"
    echo
    echo "- **target:** \`$1\`"
    echo "- **generated:** $(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date)"
    echo "- **flag filter:** \`${FLAG_PREFIX:-<generic>}\` (regex \`$FLAG_REGEX\`)"
    echo
  } > "$REPORT"
  grn "[*] report: $REPORT"
}

# run_and_report <script> <args...> : run a checker, tee full output to a log, append a section.
run_and_report(){
  local name="$1"; shift
  local log="$REPORTDIR/${name%.*}.log"
  cyn "running $name"
  "$HERE/$name" "$@" 2>&1 | tee "$log"
  {
    echo "## ${name%.*}"
    echo; echo '```'
    grep -aE '^\[=\]|LIKELY|^=== |=== .* ===|\[FLAG\]|\[\+\]|\[!\]|\[~\]|CRITICAL|HIGH|detections|-> ' "$log" \
      | _noansi | grep -vE '^\s*$' | head -70
    echo '```'; echo
  } >> "$REPORT"
}

# note_report <markdown...> : record a manual next-step branch (no checker run).
note_report(){ { echo "## manual next step"; echo; echo "$*"; echo; } >> "$REPORT"; }

# finalize_report : build the ranked flag-candidates table + close out.
finalize_report(){
  local raw
  raw="$( { grep -rhaoE "$FLAG_REGEX" "$REPORTDIR" 2>/dev/null
            [ -f "$REPORT_TGT" ] && grep -aoE "$FLAG_REGEX" "$REPORT_TGT" 2>/dev/null; } \
          | sort | uniq -c | sort -rn )"
  {
    echo "## Flag candidates (ranked)"; echo
    if [ -n "$raw" ]; then
      echo '| hits | candidate | note |'; echo '|---|---|---|'
      # prefix matches first (if a prefix is set), then the rest — each already count-sorted
      if [ -n "$FLAG_PREFIX" ]; then
        printf '%s\n' "$raw" | grep -E "[0-9] (${FLAG_PREFIX})\{" 2>/dev/null \
          | while read -r c cand; do echo "| $c | \`$cand\` | matches prefix ✓ |"; done
        printf '%s\n' "$raw" | grep -vE "[0-9] (${FLAG_PREFIX})\{" 2>/dev/null \
          | while read -r c cand; do echo "| $c | \`$cand\` | |"; done
      else
        printf '%s\n' "$raw" | while read -r c cand; do echo "| $c | \`$cand\` | |"; done
      fi
    else
      echo "_No flag-shaped strings found yet — try another checker, widen FLAG_REGEX, or dig in the artifacts below._"
    fi
    echo; echo "---"
    echo "_artifacts: \`$REPORTDIR/*.log\` and any \`*_out/\` directories in $(pwd)_"
  } >> "$REPORT"
  cyn "REPORT COMPLETE"
  grn "  $REPORT"
  # echo the ranked candidates to the console too
  [ -n "$raw" ] && { ylw "  flag candidates:"; printf '%s\n' "$raw" | sed 's/^/    /'; }
}

# doctor : report which tools are present (green) / missing (red!) per category.
doctor(){
  cyn "dependency check — run ./install.sh (or ./install.sh --category X) to fix"
  local spec="core:file,xxd,strings,binwalk,grep,python3,timeout
triage:ent,foremost,7z
crypto:openssl,hashcat,john,sage,rsactftool,ciphey
web:curl,ffuf,gobuster,sqlmap,nikto,jwt_tool
forensics:exiftool,fls,mmls,photorec,bulk_extractor,vol,hayabusa,evtx_dump,regripper
stego:zsteg,steghide,stegseek,zbarimg,sox,pngcheck,outguess
rev:ghidra,r2,gdb,objdump,ltrace,angr
pwn:checksec,ROPgadget,one_gadget,ropper
net:tshark,tcpdump,zeek,tcpflow,scapy
misc:zip2john,fcrackzip,bkcrack,pdfcrack,qpdf"
  printf '%s\n' "$spec" | while IFS=: read -r name tools; do
    [ -z "$name" ] && continue
    printf '  %-10s ' "$name"
    local t ok=0 miss=0
    IFS=,
    for t in $tools; do
      if have "$t"; then printf '\033[32m%s\033[0m ' "$t"; ok=$((ok+1))
      else printf '\033[31m%s!\033[0m ' "$t"; miss=$((miss+1)); fi
    done
    unset IFS; printf '\n'
  done
  echo
  [ -f "$WORDLIST" ] && grn "  wordlist OK : $WORDLIST" || ylw "  wordlist MISSING : $WORDLIST"
  [ -d "$SECLISTS" ] && grn "  seclists OK : $SECLISTS" || ylw "  seclists MISSING : $SECLISTS"
  [ -f "$DIRLIST" ]  && grn "  dirlist OK  : $DIRLIST"  || ylw "  dirlist MISSING  : $DIRLIST"
  { have python3 && python3 -c 'import pwn' 2>/dev/null && grn "  pwntools OK"; } || ylw "  pwntools MISSING (pip install pwntools)"
}
