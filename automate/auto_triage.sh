#!/usr/bin/env bash
# auto_triage.sh [file] [flag_prefix]  —  fingerprint + route + instant flag grep.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then F="$1"; else read -rp "[?] file: " F; fi
[ -n "$F" ] || { echo "no file given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
line(){ cyn "$@"; }

line "file type";   file "$F"
line "size";        printf '%s bytes\n' "$(wc -c < "$F")"
line "magic (hex)"; xxd "$F" | head -3
have ent && { line "entropy (hi≈encrypted)"; ent "$F" | grep -i entropy; }

line "FLAG grep (raw)"
grep -aoE "$FLAG_REGEX" "$F" | sort -u
line "FLAG grep (base64-decoded chunks)"
grep -aoE '[A-Za-z0-9+/=]{16,}' "$F" | while read -r s; do echo "$s" | base64 -d 2>/dev/null; done \
  | grep -aoE "$FLAG_REGEX" | sort -u

line "strings hits"
{ strings -n 6 "$F"; strings -e l "$F"; } | grep -aiE 'flag|ctf|secret|passw|key' | head
line "embedded files"; have binwalk && binwalk "$F"

line "ROUTE"
case "$(file -b "$F")" in
  *PNG*|*JPEG*|*image*|*bitmap*|*GIF*)   echo "-> ./auto_forensic.sh '$F'   (media/stego)";;
  *filesystem*|*"disk image"*|*"boot sector"*) echo "-> mmls '$F'; fls -r -o <off> '$F'; autopsy";;
  *pcap*|*"capture file"*|*tcpdump*)     echo "-> ./auto_pcap.sh '$F'";;
  *ELF*|*PE32*|*executable*|*Mach-O*)    echo "-> checksec --file='$F'; ltrace './$F'; ghidra";;
  *Zip*|*RAR*|*7-zip*|*archive*|*gzip*)  echo "-> 7z l '$F'   (locked? zip2john/bkcrack)";;
  *PDF*)                                 echo "-> pdfid '$F'; pdftotext -layout '$F' -; olevba";;
  *ASCII*|*text*|*Unicode*)              echo "-> ./auto_crypto.py \"\$(cat '$F')\"";;
  *)                                     echo "-> binwalk -e '$F'; foremost -i '$F' -o carved/";;
esac
