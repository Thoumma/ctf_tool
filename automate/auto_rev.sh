#!/usr/bin/env bash
# auto_rev.sh [binary] [flag_prefix]  —  STATIC reversing recon (never executes the target)
# + flag sweep. Dynamic steps (ltrace/gdb) are printed as suggestions, not run.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then SRC="$1"; else read -rp "[?] binary: " SRC; fi
[ -n "$SRC" ] || { echo "no binary given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
F="$(readlink -f "$SRC")"
OUT="rev_$(basename "$F")_out"; mkdir -p "$OUT"; cd "$OUT" || exit 1

runlog file.log file "$F"
have checksec && runlog checksec.log checksec --file="$F"

{ strings -a -n 5 "$F"; strings -a -e l "$F"; } > strings.txt 2>/dev/null
cyn "interesting strings (full set -> strings.txt)"
grep -aiE 'flag|correct|wrong|congrat|denied|nope|password|passwd|serial|licen[sc]e|secret|/bin/sh|usage|%s|%d|%x|%n' \
  strings.txt | sort -u | head -60

cyn "format & packing"
grep -aqi 'UPX!' "$F" && grn "  UPX packed -> upx -d '$F'"
case "$(file -b "$F")" in
  *.NET*|*Mono*)              grn "  .NET -> decompile with dnSpy / ILSpy";;
  *"Go BuildID"*|*"Go build"*) grn "  Go binary -> Ghidra + golang_loader_assist / GoReSym";;
esac
grep -aqiE 'pyinstaller|_MEIPASS|PYZ-' strings.txt && grn "  PyInstaller -> pyinstxtractor.py then uncompyle6/decompyle3"
grep -aqi 'ptrace' strings.txt && ylw "  references ptrace() -> anti-debug likely; patch it or 'set follow-fork-mode'"

cyn "binary info"
if have rabin2; then
  rabin2 -I "$F" 2>/dev/null | grep -iE 'arch|bits|canary|nx|pic|relro|lang|static|stripped' | head
  cyn "imports (interesting)"
  rabin2 -i "$F" 2>/dev/null | grep -iE 'strcmp|strncmp|memcmp|strstr|system|exec|popen|fopen|fgets|gets|scanf|printf|ptrace|getenv|rand|srand|crypt' | head -30
  cyn "symbols of interest (check/verify/flag/win/decrypt...)"
  rabin2 -qs "$F" 2>/dev/null | grep -iE 'main|check|verif|valid|decrypt|flag|win|secret|key|auth|compare|passwd|login' | head -30
else
  have nm      && nm "$F" 2>/dev/null | grep -iE 'main|check|verif|flag|win|secret|key|auth' | head -30
  have objdump && { cyn "dynamic imports"; objdump -T "$F" 2>/dev/null | grep -iE 'strcmp|system|gets|scanf|printf|ptrace' | head -20; }
fi

flagsweep .

cyn "next steps (manual — these may EXECUTE the binary, run only if you trust it)"
cat <<EOF
  ghidra '$F'            # decompile main()/the check function and read the logic
  ltrace '$F'            # watch strcmp(your_input, SECRET)   [executes target]
  gdb -q '$F'            # break at the compare; pwndbg/gef   [executes target]
  angr symbolic solve    # template in the cheat sheet's Reversing tab
  exploitation?          ./auto_pwn.sh '$F'
EOF
