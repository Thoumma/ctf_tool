#!/usr/bin/env bash
# auto_pwn.sh [binary] [flag_prefix]  —  pwn triage (checksec, win/danger funcs, libc) and a
# ready pwntools exploit skeleton. STATIC only: it never runs the target (offset/gadget commands
# are printed for you to run deliberately).
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HERE/config.sh"
if [ -n "${1:-}" ]; then SRC="$1"; else read -rp "[?] binary: " SRC; fi
[ -n "$SRC" ] || { echo "no binary given"; exit 1; }
[ -n "${2:-}" ] && set_flag_prefix "$2"
F="$(readlink -f "$SRC")"
OUT="pwn_$(basename "$F")_out"; mkdir -p "$OUT"; cd "$OUT" || exit 1

runlog file.log file "$F"
if have checksec; then runlog checksec.log checksec --file="$F"
else ylw "  checksec missing — install it (part of the 'pwn' category)"; fi

cyn "win / backdoor functions (ret2win targets)"
if have rabin2; then rabin2 -qs "$F" 2>/dev/null | grep -iE 'win|flag|backdoor|shell|give|cat|system|secret|admin|magic' | head
elif have nm;    then nm "$F" 2>/dev/null | grep -iE ' [tT] ' | grep -iE 'win|flag|backdoor|shell|system' | head; fi

cyn "dangerous sinks (overflow / format-string)"
{ have rabin2 && rabin2 -i "$F" 2>/dev/null | awk -F'[ .]' '{print $NF}'
  have objdump && objdump -T "$F" 2>/dev/null | awk '{print $NF}'; } 2>/dev/null \
  | grep -iwE 'gets|strcpy|strcat|sprintf|vsprintf|scanf|__isoc99_scanf|read|memcpy|system|printf|fprintf|alloca' \
  | sort -u

cyn "/bin/sh present? format specifiers present?"
strings -a "$F" 2>/dev/null | grep -nE '/bin/sh|%[0-9\$]*[sxnp]' | head

cyn "libc"
if ls "$(dirname "$F")" 2>/dev/null | grep -qiE 'libc.*\.so|ld-.*\.so'; then
  grn "  local libc present -> ret2libc feasible"; ls "$(dirname "$F")" | grep -iE 'libc|ld-' | sed 's/^/    /'
else ylw "  no local libc in the folder -> leak an address then resolve with libc.rip / local libc-database"; fi

# ---- generate a pwntools skeleton ----
SK="exploit_$(basename "$F").py"
cat > "$SK" <<PYEOF
#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("$F")
# libc = ELF("./libc.so.6")
context.log_level = "info"

def conn():
    return remote("HOST", 1337) if args.REMOTE else process(elf.path)

io = conn()
# 1) offset to saved RIP:   cyclic 200 | '$F'   ->   cyclic -l <value at crash>
off = 0
# 2) pick the technique from checksec:
#    ret2win:   payload = flat({off: elf.sym['win']})
#    ret2libc:  rop = ROP(elf); rop.puts(elf.got['puts']); rop.main(); ...leak, set libc.address, system('/bin/sh')
payload = flat({off: [
    # gadgets go here
]})
io.sendline(payload)
io.interactive()
PYEOF
grn "[*] pwntools skeleton -> $OUT/$SK"

cyn "run these deliberately (they execute the binary)"
cat <<EOF
  cyclic 200 | '$F'        ;  cyclic -l 0x6161616c       # find the saved-RIP offset
  ROPgadget --binary '$F' | grep 'pop rdi ; ret'
  one_gadget ./libc.so.6                                  # if a libc is present
EOF

flagsweep .
