#!/usr/bin/env python3
"""auto_crypto.py "<text>"   — recursively peel encodings (base64/32/16/url/rot/xor),
                               ID hashes, and flag anything that looks like a flag.
   auto_crypto.py --rsa n e c  — factordb lookup + decrypt attempt.
   Optional: pip install requests ; and `ciphey` / `rsactftool` on PATH for fallback.
"""
import sys, os, re, base64, codecs, string, subprocess, shutil

FLAG = re.compile(os.environ.get("FLAG_REGEX") or (
    re.escape(os.environ["FLAG_PREFIX"]) + r"\{[^}]{1,120}\}"
    if os.environ.get("FLAG_PREFIX") else r"[A-Za-z0-9_]{2,}\{[^}]{1,120}\}"))


def printable(b):
    try:
        t = b.decode("latin-1")
    except Exception:
        return False
    return sum(c in string.printable for c in t) / max(1, len(t)) > 0.9


def try_decodes(data: bytes):
    outs = {}
    s = data.decode("latin-1", "ignore").strip()
    # base family
    for name, fn in (("b64", lambda x: base64.b64decode(x + "===")),
                     ("b32", lambda x: base64.b32decode(x + "======")),
                     ("b16", lambda x: base64.b16decode(x.upper())),
                     ("b85", lambda x: base64.b85decode(x)),
                     ("a85", lambda x: base64.a85decode(x))):
        try:
            d = fn(re.sub(r"\s", "", s))
            if d and printable(d):
                outs[name] = d
        except Exception:
            pass
    # hex
    try:
        if re.fullmatch(r"[0-9a-fA-F\s]+", s) and len(s) > 3:
            outs["hex"] = bytes.fromhex(re.sub(r"\s", "", s))
    except Exception:
        pass
    # url
    from urllib.parse import unquote_to_bytes
    if "%" in s:
        outs["url"] = unquote_to_bytes(s)
    # rot13 / rot-all
    outs["rot13"] = codecs.encode(s, "rot_13").encode()
    # single-byte xor
    for k in range(1, 256):
        x = bytes(b ^ k for b in data)
        if FLAG.search(x.decode("latin-1", "ignore")):
            outs[f"xor{k:#x}"] = x
            break
    return outs


def recurse(data, depth=0, seen=None):
    seen = seen or set()
    txt = data.decode("latin-1", "ignore")
    for m in FLAG.findall(txt):
        print("  " * depth + f"[FLAG] {m}")
    if depth >= 6 or data in seen:
        return
    seen.add(data)
    for name, d in try_decodes(data).items():
        if d and d != data and printable(d):
            print("  " * depth + f"-> {name}: {d[:80]!r}")
            recurse(d, depth + 1, seen)


def rsa(n, e, c):
    import requests
    print(f"[*] factordb {n}")
    try:
        j = requests.get(f"http://factordb.com/api?query={n}", timeout=10).json()
        facs = [int(f) for f, _ in j["factors"]]
        print("    status", j["status"], "factors", facs)
        if j["status"] == "FF" and len(facs) >= 2:
            from math import prod
            phi = prod(p - 1 for p in facs)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            print("    plaintext:", m.to_bytes((m.bit_length() + 7) // 8, "big"))
            return
    except Exception as ex:
        print("    factordb failed:", ex)
    if shutil.which("rsactftool") or shutil.which("RsaCtfTool.py"):
        tool = shutil.which("rsactftool") or "RsaCtfTool.py"
        print("[*] falling back to RsaCtfTool --attack all")
        subprocess.run([tool, "-n", str(n), "-e", str(e), "--uncipher", str(c), "--attack", "all"])


def classify(s: str):
    """Name the single most-likely crypto area and point to the Crypto-tab card."""
    t = s.strip(); a = None
    if t.startswith("eyJ") and re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", t):
        a = "JWT -> crack HS256 secret (jwt_tool -C -d rockyou) or alg:none"
    elif "-----BEGIN" in t and "KEY" in t:
        a = "RSA/PEM key -> extract n,e; factordb; run with --rsa n e c"
    elif re.fullmatch(r"\d{40,}", t):
        a = "big integer -> RSA modulus/factor -> factordb; --rsa"
    elif re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        L = len(t); h = {32: "MD5/NTLM", 40: "SHA1", 56: "SHA224", 64: "SHA256",
                         96: "SHA384", 128: "SHA512"}.get(L)
        a = f"hex {L} -> {h + ' hash (crack: hashcat/john)' if h else 'hex bytes (xxd -r -p), then re-classify'}"
    elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) and len(t) % 4 == 0 and re.search(r"[+/=]|(?=.*[a-z])(?=.*[A-Z])", t):
        a = "Base64 -> decode (may be layered, or AES/RSA ciphertext underneath)"
    elif all(c.isalpha() or c.isspace() for c in t) and any(c.isalpha() for c in t):
        a = "alphabetic -> classical cipher (Caesar/Vigenere/substitution: dcode.fr, quipqiup)"
    elif len(s) % 16 == 0 and sum(b > 126 or b < 9 for b in s.encode("latin-1", "ignore")) > len(s) * 0.3:
        a = "16-byte-aligned high-entropy -> AES/block cipher (ECB/CBC/CTR mode attack)"
    print("[=] LIKELY AREA:", a or "unknown -> see the decode recursion below / try ciphey", "\n")


if __name__ == "__main__":
    args = sys.argv[1:] or input("[?] text (or: --rsa n e c): ").split()
    if args and args[0] != "--rsa":
        classify(args[0])
    if len(args) >= 4 and args[0] == "--rsa":
        rsa(int(args[1]), int(args[2]), int(args[3]))
    elif args:
        recurse(args[0].encode())
        if shutil.which("ciphey"):
            print("\n[*] ciphey fallback:")
            subprocess.run(["ciphey", "-t", args[0], "-q"])
    else:
        sys.exit(__doc__)
