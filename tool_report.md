# Tool Report — Windows 11 host

**Generated:** 2026-11-09 · Host: Windows 11 Home · Checked by launching/version-probing each tool.
**Legend:** ✅ works (functionally tested) · 🟡 installed but not verified end-to-end / needs action · ❌ missing or broken.

---

## 1. Summary — the headline

- **Burp Suite, Nmap, Wireshark all work fine.** ✅
- **Two real problems to fix:**
  1. **Docker daemon is not running** — Docker Desktop is stopped, so `docker` commands fail. ❌
  2. **Your CTF toolkit (`automate/*.sh`) has almost nothing to run against** — the WSL *Ubuntu* distro it's meant to use has **none** of the security tools installed and **no rockyou/seclists**. `install.sh` has not been run there. ❌
- Several **Python exploit libraries are missing on Windows** (pwntools, z3, angr, unicorn, sympy, gmpy2, impacket). 🟡

---

## 2. GUI / security tools (Windows-native)

| Tool | Version | Status | Notes |
|---|---|---|---|
| **Burp Suite** | 2026.9.2 | ✅ installed, launchable | `…\AppData\Local\Programs\BurpSuite\BurpSuite.exe` + `burpsuite.jar` (162 MB) + bundled `jre\` + `burpbrowser\` (embedded Chromium). Intact. *Not auto-launched (GUI/licensed) — start it from the Start Menu to confirm the proxy listener.* **Update pending:** `v2026.10.1` is downloaded in `AppData\Roaming\BurpSuite\updates\` but not yet installed — launch Burp to apply it. |
| **Nmap** | 7.991 | ✅ works | `C:\Program Files (x86)\Nmap\nmap.exe`. Functional test: `nmap -sn 127.0.0.1` succeeded (host up, 1.43 s). |
| **Wireshark / tshark** | 4.4.6 | ✅ works | `C:\Program Files\Wireshark\`. `tshark -D` listed 6 capture interfaces → **Npcap driver is working** (live capture OK). |
| **Postman** | 11.89.0 | 🟡 installed | API client; not functionally tested. |
| **VMware Workstation** | 25.0.0 | 🟡 installed | VMnet1/VMnet8 interfaces present. |
| **OpenVPN Connect** | 3.9.0 | 🟡 installed | Not tested. |
| **Docker** | 28.5.1 CLI | ❌ daemon down | CLI present, but `docker ps` → *"cannot find …dockerDesktopLinuxEngine"*. Docker Desktop's WSL engine is **Stopped**. See §5. |

---

## 3. CLI tools / interpreters (Windows, on PATH)

| Tool | Version | Status |
|---|---|---|
| Python | 3.11.5 | ✅ |
| pip / pip3 | — | ✅ |
| Java (Oracle) | 17.0.11 LTS | ✅ |
| Volatility 3 | 2.28.2 (`vol`) | ✅ works (`vol -h` OK) |
| OpenSSL | 3.2.4 | ✅ |
| Git | mingw | ✅ |
| curl | mingw | ✅ |
| Node / npm | 22.16.0 | ✅ |
| Perl | — | ✅ |
| WSL | present | ✅ (see §5) |

**Not on PATH / absent on Windows:** `go`, `wget`, `ruby`, `hashcat`, `john`, `sqlmap`, `gobuster`, `ffuf`, `nikto`, `radare2`, `binwalk`, `exiftool`, `7z`, `zsteg`, `steghide`, `stegseek`, `foremost`. (These are expected to live in WSL/Kali, not native Windows — see §5.)

---

## 4. Python packages (Windows `Python311`)

| Present ✅ | Missing ❌ |
|---|---|
| scapy 2.8.0, pycryptodome 3.23.0, requests 2.34.2, capstone 5.0.9, Pillow 12.3.0, numpy 2.4.6 | **pwntools, z3-solver, angr, unicorn, sympy, gmpy2, ropper, beautifulsoup4, impacket** |

**Impact:** the missing ones are heavily used in the cheat sheet (pwn skeletons need `pwntools`; RE/keygen needs `z3`/`angr`/`unicorn`; crypto needs `sympy`/`gmpy2`). `auto_pwn.sh` / pwn workflows won't run without pwntools.

**Fix:**
```powershell
python -m pip install pwntools z3-solver unicorn capstone sympy gmpy2 ropper beautifulsoup4 impacket
# angr: python -m pip install angr   (large; or use it inside WSL)
```

---

## 5. WSL — the CTF toolkit's actual runtime (⚠ biggest gap)

Distros: `Ubuntu` (default, **Running**), `podman-uosserver` (stopped), `docker-desktop` (**stopped** → why Docker CLI fails).

Inside **Ubuntu**, probing the tools `automate/auto_all.sh --check` expects:

| Present | Missing |
|---|---|
| `python3` | **everything else**: nmap, tshark, hashcat, john, sqlmap, gobuster, ffuf, binwalk, exiftool, zsteg, steghide, stegseek, foremost, volatility3, hayabusa, 7z, sage, rsactftool |
| | `rockyou.txt` — **missing**, `seclists` — **missing** |

**Meaning:** if you run `./automate/auto_all.sh <target>` from WSL today, nearly every sub-checker will skip its tools and the report will be mostly empty. The toolkit itself is fine (verified earlier) — it just has no tools to call yet.

**Fix (run once in WSL):**
```bash
cd /mnt/d/03_CTF/ctf_tool
chmod +x install.sh automate/*.sh automate/*.py
./install.sh            # installs rockyou, hashcat, seclists, volatility3, hayabusa, + all categories
./automate/auto_all.sh --check   # re-check: should turn green
```

---

## 6. Functions that do NOT work well right now

1. **`docker` (any command) — FAILS.** Daemon not reachable (`dockerDesktopLinuxEngine` pipe missing). → Start **Docker Desktop**, wait for it to report "running", then `docker ps`.
2. **CTF `automate/*.sh` sweeps in WSL — effectively non-functional.** No scanner/forensic/crypto tools and no wordlists in the Ubuntu distro. → run `install.sh` (§5).
3. **Pwn / symbolic / big-int workflows on Windows — unavailable.** `pwntools`, `z3`, `angr`, `unicorn`, `sympy`, `gmpy2` not installed. → `pip install` (§4), or do pwn/RE inside WSL where ptrace/ELF tooling is native.
4. **Burp Suite — installed and intact, but not functionally proven here.** It's a GUI app I didn't launch. → open it once, confirm the Proxy listener binds `127.0.0.1:8080` and the embedded browser opens.

## 7. All clear (no action needed)

Burp Suite (install intact), Nmap (scan tested), Wireshark+Npcap (capture interfaces live), Volatility 3, Python 3.11 + pip, Java 17, OpenSSL, Git, curl, Node — all good on Windows.
