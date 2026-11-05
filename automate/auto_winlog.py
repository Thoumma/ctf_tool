#!/usr/bin/env python3
"""auto_winlog.py [Security.evtx | dump.xml]  — DeepBlueCLI-style Windows event-log hunt.

Replicates DeepBlueCLI's detection cases and PRINTS each match with its label.
Input: a .evtx (needs `pip install python-evtx`, or the `evtx_dump` binary on PATH)
       or an already-dumped XML/text file. Prompts if no argument is given.
"""
import sys, os, re, subprocess, shutil, collections

FAIL_T = int(os.environ.get("FAIL_THRESHOLD", 10))
SPRAY_T = int(os.environ.get("SPRAY_THRESHOLD", 5))
ADMIN_T = int(os.environ.get("ADMIN_THRESHOLD", 5))

# ---- command-line / scriptblock detections (from DeepBlueCLI regexes.txt + extras) ----
CMD_REGEX = [
    (r'cmd\.exe /c echo [a-z]{6} > \\\\\.\\pipe\\[a-z]{6}', "Metasploit getsystem (named pipe)"),
    (r'%SYSTEMROOT%\\[a-zA-Z]{8}\.exe', "Metasploit 'Native upload' image path"),
    (r'FromBase64String.*IO\.Compression\.GzipStream', "Metasploit base64+gzip PowerShell payload"),
    (r'DownloadString\(.{0,3}http', "Net.WebClient DownloadString (remote fetch)"),
    (r'(?i)mimikatz', "Mimikatz reference"),
    (r'(?i)Invoke-Mimikatz', "PowerSploit Invoke-Mimikatz"),
    (r'(?i)PowerSploit', "PowerSploit usage"),
    (r'[A-Za-z0-9/+=]{500,}', "500+ consecutive Base64 chars (encoded payload)"),
    (r'(?i)powershell.*hidden.*enc', "Hidden + encoded PowerShell command"),
    (r'(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}', "PowerShell -EncodedCommand"),
    (r'(?i)-nop(rofile)?\b', "PowerShell -NoProfile"),
    (r'(?i)-w(indowstyle)?\s*hidden', "PowerShell hidden window"),
    (r'\\csc\.exe', "C# compiler csc.exe (in-memory compile)"),
    (r'\\cvtres\.exe', "cvtres.exe (PSAttack-style)"),
    (r'(?i)Register-ScheduledTask', "Register-ScheduledTask persistence (ASEP)"),
    (r'(?i)schtasks.*/create', "schtasks persistence (ASEP)"),
    (r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', "Run-key persistence (ASEP)"),
    (r'(?i)\breg(\.exe)? .*add', "Registry add (possible ASEP)"),
    (r'(?i)ADMIN\$', "Access to ADMIN$ share (lateral movement)"),
    (r'(?i)\\\\[\w.]+\\(C|ADMIN|IPC)\$', "Access to hidden share (lateral movement)"),
    (r'(?i)net\s+user\s+.*\s+/add', "Local user added via net user"),
    (r'(?i)net\s+localgroup\s+administrators\s+.*/add', "User added to local admins"),
    (r'(?i)(whoami|net group|net view|nltest|arp -a|ipconfig|systeminfo|tasklist)', "Host/recon command"),
    (r'(?i)(bloodhound|sharphound|rubeus|seatbelt|winpeas|lazagne)', "Known offensive tool"),
    (r'(?i)(Invoke-Expression|\bIEX\b)', "Invoke-Expression (IEX)"),
    (r'(?i)ExecutionPolicy\s+Bypass', "ExecutionPolicy Bypass"),
    (r'(?i)FromBase64String', "Base64 decode in command"),
    (r'(?i)(certutil|bitsadmin).*(http|urlcache|-decode)', "LOLBIN download/decode (certutil/bitsadmin)"),
    (r'(?i)rundll32.*javascript', "rundll32 javascript (squiblydoo)"),
    (r'(?i)(wscript|cscript|mshta).*http', "Script host fetching remote content"),
    (r'(?i)vssadmin.*delete.*shadows', "Shadow copy deletion (ransomware)"),
    (r'(?i)wevtutil.*cl', "Event log cleared via wevtutil"),
]
EID_LABEL = {
    1102: "Security Audit Log CLEARED", 104: "Event Log CLEARED",
    4720: "New User Created", 4722: "User Account Enabled",
    4728: "User added to GLOBAL group", 4732: "User added to LOCAL group",
    4756: "User added to UNIVERSAL group", 4648: "Explicit-credential logon (spray/lateral)",
    4672: "Admin/Sensitive-privilege logon (SeDebugPrivilege)", 4697: "Service installed (Security)",
    7045: "New Service Installed", 7030: "Interactive Service warning", 7040: "Service start-type changed",
    4698: "Scheduled Task created", 4702: "Scheduled Task updated", 5861: "WMI permanent event filter (persistence)",
    4688: "Process created", 4104: "PowerShell ScriptBlock", 4103: "PowerShell pipeline",
    1: "Sysmon ProcessCreate", 7: "Sysmon Image/DLL Loaded", 8: "Sysmon CreateRemoteThread",
    11: "Sysmon FileCreate", 13: "Sysmon RegistrySet", 3: "Sysmon NetworkConnect",
    8003: "AppLocker would-block (audit)", 8004: "AppLocker BLOCK",
}


def records(path):
    if path.lower().endswith(".evtx"):
        try:
            from Evtx.Evtx import Evtx
            with Evtx(path) as log:
                for r in log.records():
                    yield r.xml()
            return
        except ImportError:
            if shutil.which("evtx_dump"):
                out = subprocess.run(["evtx_dump", "-o", "xml", path], capture_output=True, text=True).stdout
                for m in re.split(r'(?=<Event[ >])', out):
                    if m.strip():
                        yield m
                return
            sys.exit("[-] install python-evtx (pip install python-evtx) or put evtx_dump on PATH, "
                     "or pass an XML dump: evtx_dump -o xml x.evtx > x.xml")
    else:
        data = open(path, encoding="utf-8", errors="ignore").read()
        for m in re.split(r'(?=<Event[ >])', data):
            if m.strip():
                yield m


def eid(xml):
    m = re.search(r'<EventID[^>]*>(\d+)', xml)
    return int(m.group(1)) if m else -1


def fld(xml, name):
    m = re.search(r'Name=["\']%s["\'][^>]*>([^<]*)' % re.escape(name), xml)
    return m.group(1) if m else ""


def cmdline(xml):
    return " ".join(filter(None, [fld(xml, "CommandLine"), fld(xml, "NewProcessName"),
                                   fld(xml, "ScriptBlockText"), fld(xml, "Image"),
                                   fld(xml, "ServiceFileName"), fld(xml, "ImagePath")]))


def hunt(path):
    fail = collections.Counter()          # 4625 by target user
    spray = collections.defaultdict(set)  # 4648 source -> {targets}
    admin = collections.Counter()         # 4672 by user
    n = hits = 0
    print(f"[*] scanning {path} (DeepBlueCLI-style rules)\n")
    for xml in records(path):
        n += 1
        e = eid(xml)

        if e in (1102, 104, 8004, 5861, 7045, 4697, 4698, 4702, 4720, 4722,
                 4728, 4732, 4756, 7030, 8, 7030):
            det = fld(xml, "TargetUserName") or fld(xml, "ServiceName") or fld(xml, "SubjectUserName")
            if e in (7045, 4697):
                sn = fld(xml, "ServiceName")
                if re.fullmatch(r'[A-Za-z]{16}', sn) or re.fullmatch(r'[A-Za-z]{22}', sn):
                    print(f"  [{e}] Metasploit-style random service name :: {sn}"); hits += 1
            print(f"  [{e}] {EID_LABEL.get(e,'')} :: {det}"); hits += 1

        if e == 4672:
            admin[fld(xml, "SubjectUserName")] += 1
        if e == 4625:
            fail[fld(xml, "TargetUserName")] += 1
        if e == 4648:
            spray[fld(xml, "SubjectUserName")].add(fld(xml, "TargetUserName"))

        if e in (4688, 4104, 4103, 1, 7, 13):
            cl = cmdline(xml)
            for rx, label in CMD_REGEX:
                if re.search(rx, cl):
                    print(f"  [{e}] {label}\n        -> {cl[:160]}"); hits += 1
            # obfuscation heuristic
            if cl and (cl.count("`") > 4 or cl.count("^") > 4 or len(re.findall(r'\+', cl)) > 15):
                print(f"  [{e}] Obfuscated command (escape/concat heavy)\n        -> {cl[:120]}"); hits += 1
            if e == 7 and fld(xml, "Signed").lower() == "false":
                print(f"  [7] Unsigned DLL/image loaded :: {fld(xml,'ImageLoaded')}"); hits += 1
            if e == 8:
                print(f"  [8] CreateRemoteThread -> {fld(xml,'TargetImage')} from {fld(xml,'SourceImage')}"); hits += 1

    # ---- count-based detections ----
    for u, c in fail.items():
        if c >= FAIL_T:
            print(f"  [4625] High logon failures for one account :: {u} ({c} fails) — bruteforce"); hits += 1
    if sum(fail.values()) >= FAIL_T * 3 and len(fail) >= SPRAY_T:
        print(f"  [4625] High TOTAL logon failures across {len(fail)} accounts ({sum(fail.values())})"); hits += 1
    for src, tgts in spray.items():
        if len(tgts) >= SPRAY_T:
            print(f"  [4648] Password-spray pattern :: {src} used explicit creds vs {len(tgts)} accounts"); hits += 1
    for u, c in admin.items():
        if c >= ADMIN_T:
            print(f"  [4672] Multiple admin logons for one account :: {u} ({c})"); hits += 1

    print(f"\n[=] {n} events scanned, {hits} detections.")
    if not hits:
        print("[=] clean by these rules — also try: chainsaw hunt + sigma, or run DeepBlue.ps1 natively.")


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else input("[?] evtx / xml dump: ").strip()
    if not p:
        sys.exit("no file given")
    hunt(p)
