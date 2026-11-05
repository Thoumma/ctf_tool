# CTF Tool

A self-contained CTF toolkit: an offline techniques cheat sheet + a set of "point-it-and-go"
automation scripts that recon/triage a target, classify what it likely is, and sweep for the flag —
aggregating everything into one `report.md`.

```
ctf_tool/
├── CTF_Techniques_Cheatsheet.html   # offline, tabbed reference (open in any browser)
├── install.sh                       # one-shot Kali/WSL tool installer
├── README.md                        # this file
└── automate/
    ├── config.sh         # shared settings + helpers (EDIT THIS to tune everything)
    ├── auto_all.sh       # MASTER dispatcher -> runs the right checker, builds report.md
    ├── auto_triage.sh    # fingerprint any file + route
    ├── auto_forensic.sh  # stego/media/file: exiftool, binwalk, zsteg, steghide, stegseek, ...
    ├── auto_pcap.sh      # network: protocols, objects, creds, DNS, USB-HID, carving
    ├── auto_mem.sh       # memory: Volatility 3 recon battery
    ├── auto_hayabusa.sh  # EVTX: Hayabusa (Sigma) timeline + summary  (PRIMARY log check)
    ├── auto_winlog.py    # EVTX: DeepBlueCLI-style rules (no-binary fallback)
    ├── auto_dirsweep.sh  # a folder of mixed files / writeup PDFs -> extract text, sweep flags
    ├── auto_rev.sh       # binary: static reversing recon (strings/imports/symbols, no execution)
    ├── auto_pwn.sh       # binary: pwn triage (checksec/win/sinks) + pwntools exploit skeleton
    ├── auto_web.py       # web recon + active vuln-area classifier (rate-limit safe)
    └── auto_crypto.py    # classify crypto area + peel encodings + RSA (factordb/RsaCtfTool)
```

## Quick start (Kali / WSL2)

```bash
cd ctf_tool
chmod +x install.sh automate/*.sh automate/*.py
./install.sh                         # rockyou, hashcat, seclists, volatility3, hayabusa, + all categories
./automate/auto_all.sh --check       # dependency doctor: green = ready, red! = missing
```

> Windows user? Run everything from **WSL2** (`wsl --install -d kali-linux`). Your drive is at
> `/mnt/d`, so this folder is `/mnt/d/03_CTF/ctf_tool`. Hayabusa & DeepBlueCLI can also run natively
> on Windows. If you ever edit a script in a Windows editor, run `dos2unix automate/*` (CRLF breaks bash).

## Usage

```bash
# interactive — just type the target when prompted:
./automate/auto_all.sh

# or pass it, with an optional flag prefix to scope the sweep:
./automate/auto_all.sh capture.pcap            CSG_FLAG
./automate/auto_all.sh dump.mem                CSG_FLAG
./automate/auto_all.sh "http://10.10.10.5/"    CSG_FLAG
./automate/auto_all.sh ./challenge_folder/     CSG_FLAG
```

### Working a live challenge

Drop the files you're given into **`challenge/`** during the event, then point the tool at them
(the `challenge/` contents are gitignored, so they never get pushed):

```bash
./automate/auto_all.sh challenge/suspicious.pcap CSG_FLAG   # one file
./automate/auto_all.sh challenge/ CSG_FLAG                  # a whole dropped folder
```

`auto_all.sh` detects the target type and runs the right checker:

| target | checker |
|---|---|
| `http(s)://…` | `auto_web.py` |
| `.pcap/.pcapng/.cap` | `auto_pcap.sh` |
| `.mem/.raw/.vmem/.dmp/…` | `auto_mem.sh` |
| `.evtx` | `auto_hayabusa.sh` (or `auto_winlog.py` if no hayabusa binary) |
| directory **with** `.evtx` | `auto_hayabusa.sh` |
| directory (mixed files / PDFs) | `auto_dirsweep.sh` |
| image/audio/pdf/office | `auto_forensic.sh` |
| text / cipher | `auto_crypto.py` |
| ELF/PE/Mach-O binary | `auto_rev.sh` + `auto_pwn.sh` |

Every run writes **`report_<target>/report.md`**: run metadata, a captured section per checker,
and a **ranked flag-candidate table** (prefix matches first). Each sub-script also works standalone
(run it with no argument and it prompts).

## Configuration — `automate/config.sh`

One place to tune everything (all overridable inline or via env):

| setting | default | purpose |
|---|---|---|
| `FLAG_PREFIX` | *(empty)* | e.g. `CSG_FLAG` → sweeps match `CSG_FLAG{…}` only (kills decoys) |
| `WORDLIST` | `/usr/share/wordlists/rockyou.txt` | cracking list (stegseek, john, …) |
| `SECLISTS` | `/usr/share/seclists` | SecLists root |
| `HAYABUSA` | *(auto-detect)* | path to the hayabusa binary |
| `VOL` | *(auto-detect)* | volatility3 command |
| `TOOL_TIMEOUT` | `120` | seconds per external tool (0 = unlimited) |
| `HEAD_LINES` | `80` | console preview; full output still saved to `*.log` |
| `WEB_DELAY` / `WEB_BUDGET` | `0.4` / `400` | web request spacing + cap (rate-limit safety) |
| `FAIL/SPRAY/ADMIN_THRESHOLD` | `10/5/5` | `auto_winlog.py` detection thresholds |

```bash
# examples
FLAG_PREFIX=CSG_FLAG ./automate/auto_all.sh chall.png
WEB_DELAY=1 WEB_BUDGET=150 ./automate/auto_web.py http://host/     # go slower if throttled
```

## The cheat sheet

Open `CTF_Techniques_Cheatsheet.html` in any browser (fully offline). Tabbed by category
(Crypto with a Python script per attack type, Web, Forensics disk/memory/network, Stego, Reversing,
Pwn, OSINT, Misc) plus a **Setup** tab (tool↔category map) and an **Automate_Check** tab documenting
every script above. Press `/` to search across all tabs; click **Copy** on any block.

## Validate before an event

Run against data where you know the answers — e.g. a 2024 answer-key folder — and confirm the flags
come back:

```bash
./automate/auto_all.sh "../Answer Keys_2024" CSG_FLAG   # should list all CSG_FLAG{...} in the report
```

## Notes & limits

- **Authorized targets only.** `auto_web.py` sends live injection payloads; use it on CTF/lab hosts you own.
- **Hayabusa** needs its binary (release or `cargo build`); `install.sh` fetches the Linux release.
- **PDF text** needs `pdftotext` (poppler-utils); without it `auto_dirsweep.sh` falls back to `strings`.
- `auto_crypto.py` decodes a string that is *entirely* an encoding; flags buried inside prose need manual carving.
- Scripts are best-effort: a missing tool is skipped (not fatal). Run `auto_all.sh --check` to see gaps.
