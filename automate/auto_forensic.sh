#!/usr/bin/env bash
# auto_forensic.sh [file] [flag_prefix]  —  run EVERY stego/forensic extractor (each with a
# timeout, full output saved to *.log), then flag-sweep the whole output dir.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then SRC="$1"; else read -rp "[?] file: " SRC; fi
[ -n "$SRC" ] || { echo "no file given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
F="$(readlink -f "$SRC")"
OUT="forensic_$(basename "$F")_out"; mkdir -p "$OUT"; cd "$OUT" || exit 1
ext="${F##*.}"; ext="${ext,,}"
to(){ if have timeout && [ "$TOOL_TIMEOUT" -gt 0 ]; then timeout "$TOOL_TIMEOUT" "$@"; else "$@"; fi; }

runlog file.log file "$F"
have exiftool && runlog exiftool.log exiftool "$F"
{ strings -n 6 "$F"; strings -e l "$F"; strings -e b "$F"; } > strings.txt
grn "[*] strings -> strings.txt ($(wc -l < strings.txt) lines)"

have binwalk  && runlog binwalk.log binwalk "$F"
have binwalk  && to binwalk -e --dd='.*' "$F" -C . >/dev/null 2>&1
have foremost && to foremost -i "$F" -o foremost_out >/dev/null 2>&1
have bulk_extractor && to bulk_extractor -o be_out "$F" >/dev/null 2>&1

case "$ext" in png|bmp) have zsteg && runlog zsteg.log zsteg -a "$F";; esac
case "$ext" in
  jpg|jpeg|bmp|wav|au)
    have steghide && { steghide extract -sf "$F" -p "" -xf steg_blank.out 2>/dev/null && grn "[+] steghide blank-pass hit!"; }
    have stegseek && runlog stegseek.log stegseek "$F" "$WORDLIST" steg_crack.out ;;
esac
have outguess && outguess -r "$F" outguess.out 2>/dev/null
have pngcheck && runlog pngcheck.log pngcheck -v "$F"
case "$ext" in wav|mp3|flac|ogg) have sox && sox "$F" -n spectrogram -o spectrogram.png 2>/dev/null && grn "[+] spectrogram.png";; esac
case "$ext" in
  pdf) have pdfid && runlog pdfid.log pdfid "$F"; have pdfimages && pdfimages -all "$F" img >/dev/null 2>&1;;
  doc*|xls*|ppt*) have olevba && runlog olevba.log olevba "$F";;
esac

flagsweep .
grn "[*] review: strings.txt, *.log, _*.extracted/, foremost_out/, be_out/, spectrogram.png"
