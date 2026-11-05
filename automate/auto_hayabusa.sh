#!/usr/bin/env bash
# auto_hayabusa.sh [file.evtx | evtx_dir]  —  Hayabusa (Sigma) forensic timeline + auto-summary.
# Runs a full detection scan with the rule-wizard disabled, then parses the CSV and PRINTS the
# findings grouped by level (critical/high/...), the CRITICAL+HIGH alerts, MITRE tactics, and a
# logon summary. Prompts for the target if none given.
#
# Needs the hayabusa BINARY (this folder is the source). Get one of:
#   - release:  github.com/Yamato-Security/hayabusa/releases  (put it on PATH or set HAYABUSA=)
#   - build:    cd <src> && cargo build --release   -> target/release/hayabusa
set -u
HAYA_HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; . "$HAYA_HERE/config.sh"

if [ -n "${1:-}" ]; then T="$1"; else read -rp "[?] evtx file or directory: " T; fi
[ -n "$T" ] || { echo "nothing given"; exit 1; }

# ---- locate the hayabusa binary ----
HB="${HAYABUSA:-}"
if [ -z "$HB" ]; then
  for c in hayabusa hayabusa.exe; do
    command -v "$c" >/dev/null 2>&1 && { HB="$(command -v "$c")"; break; }
  done
fi
if [ -z "$HB" ]; then
  for c in "$HOME/tools/hayabusa/hayabusa" \
           "/d/09_Tools-Portable/installers/hayabusa/target/release/hayabusa" \
           "/d/09_Tools-Portable/installers/hayabusa"/hayabusa-*-* ; do
    [ -x "$c" ] && { HB="$c"; break; }
  done
fi
if [ -z "$HB" ]; then
  echo "[-] hayabusa binary not found."
  echo "    -> set HAYABUSA=/path/to/hayabusa  (release from Yamato-Security/hayabusa/releases)"
  echo "    -> or build: cargo build --release   (binary lands in target/release/)"
  echo "    (fallback with no binary: ./auto_winlog.py <evtx>  — DeepBlueCLI-style rules)"
  exit 1
fi
echo "[*] hayabusa: $HB"

# ---- rules (Sigma) present? update if the bundled submodule is empty ----
BINDIR="$(cd "$(dirname "$HB")" && pwd)"
RULES="$BINDIR/rules"
if [ ! -d "$RULES" ] || [ -z "$(ls -A "$RULES" 2>/dev/null)" ]; then
  echo "[*] no rules next to binary — running update-rules"
  ( cd "$BINDIR" && "$HB" update-rules ) || echo "[!] update-rules failed; pass -r to a rules dir"
fi
RULEARG=(); [ -d "$RULES" ] && [ -n "$(ls -A "$RULES" 2>/dev/null)" ] && RULEARG=(-r "$RULES")

# ---- input: -d for directory, -f for a single evtx ----
if [ -d "$T" ]; then IN=(-d "$T"); else IN=(-f "$T"); fi
OUT="hayabusa_$(basename "$T")_out"; mkdir -p "$OUT"; CSV="$OUT/timeline.csv"
PY="$(command -v python3 || command -v python)"

echo "[*] scanning (verbose profile, all levels, no wizard)..."
"$HB" csv-timeline "${IN[@]}" "${RULEARG[@]}" -o "$CSV" -p verbose -m informational -w -C -U 2>&1 | tail -45

echo ""; echo "[*] logon summary:"
"$HB" logon-summary "${IN[@]}" 2>/dev/null | tail -25

# ---- parse the CSV and tell us what matched ----
[ -z "$PY" ] && { echo "[!] python not found; open $CSV manually"; exit 0; }
"$PY" - "$CSV" <<'PYEOF'
import csv, sys, collections
path = sys.argv[1]
try:
    rows = list(csv.DictReader(open(path, encoding="utf-8", errors="ignore")))
except FileNotFoundError:
    sys.exit("[-] no CSV produced (scan may have found nothing or binary errored)")
if not rows:
    sys.exit("[=] Hayabusa produced no detections.")
cols = {c.lower(): c for c in rows[0].keys()}
L  = cols.get("level"); TT = cols.get("ruletitle"); TS = cols.get("timestamp")
CP = cols.get("computer"); MT = cols.get("mitretactics")
lv = collections.Counter(); byrule = collections.Counter(); tactics = collections.Counter()
critical = []
for r in rows:
    lvl = (r.get(L) or "").lower()
    lv[lvl] += 1
    byrule[(lvl, r.get(TT))] += 1
    for t in (r.get(MT) or "").split(" ⇒ ")[0].split(","):
        t = t.strip()
        if t: tactics[t] += 1
    if lvl in ("critical", "high"):
        critical.append((r.get(TS), lvl, r.get(CP), r.get(TT)))

print("\n================= HAYABUSA SUMMARY =================")
print(f"[=] total detections: {len(rows)}")
print("[=] by level:")
for k in ("critical", "high", "medium", "low", "informational"):
    if lv.get(k): print(f"       {k:13} {lv[k]}")
print("\n[=] CRITICAL / HIGH alerts (rule :: count):")
hc = [(l, t, c) for (l, t), c in byrule.most_common() if l in ("critical", "high")]
for l, t, c in hc or [("", "(none)", 0)]:
    print(f"       [{l:8}] {t}  x{c}")
if tactics:
    print("\n[=] MITRE ATT&CK tactics seen:")
    for t, c in tactics.most_common(10):
        print(f"       {t}  x{c}")
print("\n[=] first critical/high events (time :: host :: rule):")
for ts, lvl, cp, tt in critical[:20]:
    print(f"       {ts}  [{lvl}]  {cp}  {tt}")
print(f"\n[*] full timeline CSV: {path}")
PYEOF
