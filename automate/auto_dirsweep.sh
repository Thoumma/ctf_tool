#!/usr/bin/env bash
# auto_dirsweep.sh [dir] [flag_prefix]  —  recursively sweep a folder of MIXED files for flags.
# Extracts text from PDFs (pdftotext) and office docs, runs strings on everything else, and
# reports per-file flag hits. Good for writeup/answer-key folders and bundles of challenges.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then SRC="$1"; else read -rp "[?] directory: " SRC; fi
[ -n "$SRC" ] || { echo "no directory given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
D="$(readlink -f "$SRC")"
[ -d "$D" ] || { echo "[-] not a directory: $D"; exit 1; }

cyn "file inventory (by extension)"
find "$D" -type f 2>/dev/null | sed 's/.*\.//; s/.*\//(none)/' | tr 'A-Z' 'a-z' \
  | sort | uniq -c | sort -rn | head -30
grn "[*] total files: $(find "$D" -type f 2>/dev/null | wc -l)"

cyn "FLAG SWEEP (extracted text: PDF via pdftotext, else strings) — per file"
find "$D" -type f 2>/dev/null | while IFS= read -r f; do
  case "${f,,}" in
    *.pdf)              have pdftotext && txt="$(pdftotext -layout "$f" - 2>/dev/null)" || txt="$(strings -n 5 "$f" 2>/dev/null)";;
    *.doc|*.docx|*.odt) have libreoffice && txt="$(libreoffice --headless --cat "$f" 2>/dev/null)" || txt="$(strings -n 5 "$f" 2>/dev/null)";;
    *)                  txt="$(strings -n 5 "$f" 2>/dev/null)";;
  esac
  hits="$(printf '%s' "$txt" | grep -aoE "$FLAG_REGEX" | sort -u)"
  [ -n "$hits" ] && printf '%s\n' "$hits" | sed "s|^|  ${f#$D/}: |"
done | sort -u

grn "[*] tip: this also sweeps answer-key / writeup PDFs — handy to verify your own solves."
