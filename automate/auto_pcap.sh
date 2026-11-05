#!/usr/bin/env bash
# auto_pcap.sh [pcap] [flag_prefix]  —  full PCAP triage (timeouts, full output saved) + flag sweep.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then SRC="$1"; else read -rp "[?] pcap: " SRC; fi
[ -n "$SRC" ] || { echo "no pcap given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
F="$(readlink -f "$SRC")"
OUT="pcap_$(basename "$F")_out"; mkdir -p "$OUT"; cd "$OUT" || exit 1
to(){ if have timeout && [ "$TOOL_TIMEOUT" -gt 0 ]; then timeout "$TOOL_TIMEOUT" "$@"; else "$@"; fi; }

have capinfos && runlog capinfos.log capinfos "$F"
runlog phs.log  tshark -r "$F" -q -z io,phs
runlog conv.log tshark -r "$F" -q -z conv,tcp

for proto in http smb tftp imf; do
  mkdir -p "obj_$proto"; to tshark -r "$F" --export-objects "$proto,obj_$proto" >/dev/null 2>&1
done
runlog httpreq.log tshark -r "$F" -Y 'http.request' -T fields -e http.host -e http.request.uri
tshark -r "$F" -Y 'dns' -T fields -e dns.qry.name 2>/dev/null | sort -u > dns_names.txt

cyn "cleartext creds (FTP/HTTP-basic)"
tshark -r "$F" -Y 'ftp.request.command=="USER" || ftp.request.command=="PASS"' -T fields -e ftp.request.arg 2>/dev/null | tee creds.txt
tshark -r "$F" -Y 'http.authorization' -T fields -e http.authorization 2>/dev/null | tee -a creds.txt

cyn "USB HID keystrokes -> usb_hid.txt (feed to ctf-usb-keyboard-parser)"
tshark -r "$F" -Y 'usb.capdata' -T fields -e usb.capdata 2>/dev/null | sed 's/://g' > usb_hid.txt

have tcpflow  && { mkdir -p streams; to tcpflow -r "$F" -o streams >/dev/null 2>&1; }
have foremost && to foremost -i "$F" -o carved >/dev/null 2>&1

flagsweep .
grn "[*] review: obj_http/, streams/, carved/, dns_names.txt, usb_hid.txt, creds.txt"
