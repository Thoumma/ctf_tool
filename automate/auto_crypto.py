#!/usr/bin/env python3
"""auto_crypto.py "<text>"   — recursively peel encodings (base64/32/16/url/rot/xor),
                               ID hashes, and flag anything that looks like a flag.
   auto_crypto.py --rsa n e c  — factordb lookup + decrypt attempt.
   auto_crypto.py --lext ALGO HASH MSG APPEND KEYLEN   — Merkle-Damgard length extension
       ALGO = sha1|sha256 ; KEYLEN = exact int, or a 'lo-hi' range to enumerate.
       MSG/APPEND are latin-1 text, or 'hex:DEADBEEF' for raw bytes.
   auto_crypto.py --gcd N1 N2 [N3 ...]  — factor RSA moduli that share a prime (GCD attack).
   auto_crypto.py --mtp CT1 CT2 [...]   — break stream-cipher nonce/IV reuse (many-time pad);
       CTs are hex, same keystream; set FLAG_PREFIX to crib-anchor the recovery.
   auto_crypto.py --selftest   — verify the engines against known-good references.
   Optional: pip install requests ; and `ciphey` / `rsactftool` on PATH for fallback.
"""
import sys, os, re, base64, codecs, string, subprocess, shutil, struct
from math import gcd
from urllib.parse import quote

def _flag_regex():
    if os.environ.get("FLAG_REGEX"):
        return os.environ["FLAG_REGEX"]
    pre = os.environ.get("FLAG_PREFIX")
    if pre:  # FLAG_PREFIX may be an alternation, e.g. pwnsec|psctf|ctf
        alts = "|".join(re.escape(p) for p in pre.split("|") if p)
        return rf"(?:{alts})\{{[^}}]{{1,120}}\}}"
    return r"[A-Za-z0-9_]{2,}\{[^}]{1,120}\}"


FLAG = re.compile(_flag_regex())


def _shift_char(c, sh):
    if c.isalpha():
        base = 65 if c.isupper() else 97
        return chr((ord(c) - base + sh) % 26 + base)
    return c


def printable(b):
    try:
        t = b.decode("latin-1")
    except Exception:
        return False
    return sum(c in string.printable for c in t) / max(1, len(t)) > 0.9


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


# Strict, charset/length-validated decoders. Returning None (instead of decoding
# junk) is what keeps the recursion from chasing false positives.
def _dec_b64(x):
    core = re.sub(r"\s", "", x).rstrip("=")
    if len(core) < 4 or len(core) % 4 == 1 or not re.fullmatch(r"[A-Za-z0-9+/]+", core):
        return None
    return _safe(lambda: base64.b64decode(core + "=" * (-len(core) % 4), validate=True))


def _dec_b64url(x):  # only when it actually uses the URL-safe alphabet ( - or _ )
    core = re.sub(r"\s", "", x).rstrip("=")
    if len(core) < 4 or len(core) % 4 == 1 or not re.fullmatch(r"[A-Za-z0-9_\-]+", core) \
            or not re.search(r"[_\-]", core):
        return None
    return _safe(lambda: base64.urlsafe_b64decode(core + "=" * (-len(core) % 4)))


def _dec_b32(x):
    core = re.sub(r"\s", "", x).upper().rstrip("=")
    if len(core) < 8 or not re.fullmatch(r"[A-Z2-7]+", core):
        return None
    return _safe(lambda: base64.b32decode(core + "=" * (-len(core) % 8)))


def _dec_b85(x):
    core = re.sub(r"\s", "", x)
    return _safe(lambda: base64.b85decode(core)) if len(core) >= 5 else None


def _dec_a85(x):
    core = re.sub(r"\s", "", x)
    return _safe(lambda: base64.a85decode(core)) if len(core) >= 5 else None


def _dec_hex(x):
    core = re.sub(r"\s", "", x)
    if len(core) <= 3 or len(core) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", core):
        return None
    return _safe(lambda: bytes.fromhex(core))


def _dec_url(x):
    if "%" not in x:
        return None
    from urllib.parse import unquote_to_bytes
    return _safe(lambda: unquote_to_bytes(x))


_DECODERS = (("b64", _dec_b64), ("b64url", _dec_b64url), ("b32", _dec_b32),
             ("b85", _dec_b85), ("a85", _dec_a85), ("hex", _dec_hex), ("url", _dec_url))


# ---------------- classical ciphers (PicoCTF-tier) ----------------
_MORSE = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
          '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
          '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U',
          '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0',
          '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6',
          '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
          '-..-.': '/', '-....-': '-', '.--.-.': '@', '---...': ':'}


def _dec_morse(s):
    if not re.fullmatch(r"[.\-/|\s]+", s) or '.' not in s or '-' not in s:
        return None
    words = re.split(r"\s*[/|]\s*|\s{2,}", s.strip())
    out = " ".join("".join(_MORSE.get(c, '') for c in w.split()) for w in words)
    return out.encode() if out.strip() else None


def _dec_atbash(s):
    return "".join(chr(155 - ord(c)) if c.isupper() else chr(219 - ord(c)) if c.islower() else c
                   for c in s).encode()


def _rail_decrypt(s, rails):
    if rails < 2 or rails >= len(s):
        return None
    patt, r, d = [], 0, 1
    for _ in range(len(s)):
        patt.append(r)
        d = 1 if r == 0 else -1 if r == rails - 1 else d
        r += d
    counts = [patt.count(i) for i in range(rails)]
    idx, rows = 0, []
    for cnt in counts:
        rows.append(s[idx:idx + cnt]); idx += cnt
    pos = [0] * rails
    res = []
    for p in patt:
        res.append(rows[p][pos[p]]); pos[p] += 1
    return "".join(res)


_EN_FREQ = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.0015, 0.0077,
            0.040, 0.024, 0.067, 0.075, 0.019, 0.00095, 0.060, 0.063, 0.091, 0.028, 0.0098,
            0.024, 0.0015, 0.020, 0.00074]


def _best_shift(col):
    best, bs = 0, 1e18
    n = len(col) or 1
    for sh in range(26):
        cnt = [0] * 26
        for c in col:
            cnt[(ord(c) - 65 - sh) % 26] += 1
        chi = sum((cnt[i] - n * _EN_FREQ[i]) ** 2 / (n * _EN_FREQ[i]) for i in range(26))
        if chi < bs:
            bs, best = chi, sh
    return best


def _vigenere_auto(s):
    """Yield (keyguess, plaintext) for key lengths 1..12 via per-column chi-square."""
    letters = [c for c in s.upper() if c.isalpha()]
    if len(letters) < 12:
        return
    for klen in range(1, 13):
        key = [_best_shift(letters[i::klen]) for i in range(klen)]
        ki, out = 0, []
        for c in s:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                out.append(chr((ord(c) - base - key[ki % klen]) % 26 + base)); ki += 1
            else:
                out.append(c)
        yield "".join(chr(k + 97) for k in key), "".join(out)


def try_decodes(data: bytes):
    outs = {}
    s = data.decode("latin-1", "ignore").strip()
    for name, fn in _DECODERS:
        d = fn(s)
        if d and d != data and printable(d):
            outs[name] = d
    texty = s and sum(c.isalpha() for c in s) >= max(3, 0.6 * len(s))
    # rot13 / atbash — deterministic single outputs, only on texty input
    if texty:
        outs["rot13"] = codecs.encode(s, "rot_13").encode()
        ab = _dec_atbash(s)
        if ab != data:
            outs["atbash"] = ab
    # morse — safe, gated on the morse charset
    m = _dec_morse(s)
    if m:
        outs["morse"] = m
    # rail-fence & vigenere are BRUTE ciphers -> only with a concrete FLAG_PREFIX
    # (against the loose generic regex they synthesize stray "word{...}" false positives)
    if os.environ.get("FLAG_PREFIX"):
        if texty and len(s) < 5000:
            for rails in range(2, min(12, len(s))):
                d = _rail_decrypt(s, rails)
                if d and FLAG.search(d):
                    outs[f"rail{rails}"] = d.encode()
            for kguess, dec in _vigenere_auto(s):
                if FLAG.search(dec):
                    outs[f"vig(key~{kguess})"] = dec.encode()
    # caesar: all 25 shifts — surface any shift that reveals a flag.
    # Only letters shift (braces/digits pass through), so run it on any texty string
    # that contains letters — including real ciphertext like "IODJ{fdhvdu}".
    if s and len(s) < 20000 and any(c.isalpha() for c in s) and printable(data):
        for sh in range(1, 26):
            shifted = "".join(_shift_char(c, sh) for c in s)
            if FLAG.search(shifted):
                outs[f"caesar+{sh}"] = shifted.encode()
    # single-byte xor brute — ONLY with a concrete FLAG_PREFIX. Against the loose generic
    # regex, XOR of ordinary text keeps synthesizing stray "word{...}" false positives
    # (XOR of English stays mostly printable, so a ratio gate can't filter them).
    if os.environ.get("FLAG_PREFIX"):
        for k in range(1, 256):
            x = bytes(b ^ k for b in data)
            if FLAG.search(x.decode("latin-1", "ignore")):
                outs[f"xor{k:#x}"] = x
    # repeating-key xor via crib-drag against the known flag prefix.
    # Appending "{" to the crib (flags are PREFIX{...}) gives one more key byte,
    # so a 3-char prefix like CSG recovers keys up to length 4.
    cribs = [c for c in (os.environ.get("FLAG_PREFIX") or "").split("|") if c]
    seen_keys = set(); seen_out = set()
    for crib in cribs:
        if len(data) < len(crib):
            continue
        cb = (crib + "{").encode()
        for off in range(len(data) - len(cb) + 1):
            keyseg = bytes(data[off + i] ^ cb[i] for i in range(len(cb)))
            if not all(32 <= b < 127 for b in keyseg):
                continue
            # keyseg[i] is the key byte at stream position (off+i) -> key index (off+i) % klen.
            # Only trust klen where the crib spans >=2 full key periods: that over-determines
            # the key, so a wrong offset fails the consistency check instead of forcing a
            # spurious flag. (Reach: a 6-char prefix recovers keys up to length 3.)
            for klen in range(1, len(cb) // 2 + 1):
                key = [None] * klen
                ok = True
                for i, b in enumerate(keyseg):
                    idx = (off + i) % klen
                    if key[idx] is None:
                        key[idx] = b
                    elif key[idx] != b:
                        ok = False; break
                if not ok or any(k is None for k in key):
                    continue  # crib didn't cover every byte of a klen-period key
                key = bytes(key)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                dec = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
                # Strict gate: crib-drag can FORCE the crib to appear at any offset,
                # so a wrong key yields garbage with a spurious flag inside. The real
                # solve is ~100% clean text — require every byte printable/whitespace.
                if dec in seen_out:
                    continue
                if FLAG.search(dec.decode("latin-1", "ignore")) and \
                   all(32 <= b < 127 or b in (9, 10, 13) for b in dec):
                    outs[f"xorkey={key!r}"] = dec
                    seen_out.add(dec)
    return outs


def recurse(data, depth=0, seen=None, budget=None):
    seen = set() if seen is None else seen
    budget = [600] if budget is None else budget   # global node cap -> no blowup/hang
    txt = data.decode("latin-1", "ignore")
    for m in dict.fromkeys(FLAG.findall(txt)):      # dedupe repeats at this node
        print("  " * depth + f"[FLAG] {m}")
    if depth >= 6 or data in seen or budget[0] <= 0:
        if budget[0] <= 0 and depth == 0:
            print("[!] decode budget reached — widen manually if needed")
        return
    seen.add(data); budget[0] -= 1
    for name, d in try_decodes(data).items():
        if d and d != data and d not in seen and printable(d):
            print("  " * depth + f"-> {name}: {d[:80]!r}")
            recurse(d, depth + 1, seen, budget)


# ---------------- Merkle-Damgard length extension (sha1 / sha256) ----------------
# Forge H(secret || orig || glue || append) knowing only H(secret||orig) and len(secret),
# without the secret. Works on any MD construction with big-endian length padding.
_K256 = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]


def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff
def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _sha256_block(state, block):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25); ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K256[i] + w[i]) & 0xffffffff
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22); maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xffffffff
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
    return [(x + y) & 0xffffffff for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def _sha1_block(state, block):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 80):
        w.append(_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:   f = (b & c) | (~b & d); k = 0x5a827999
        elif i < 40: f = b ^ c ^ d;          k = 0x6ed9eba1
        elif i < 60: f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc
        else:        f = b ^ c ^ d;          k = 0xca62c1d6
        t = (_rotl(a, 5) + f + e + k + w[i]) & 0xffffffff
        e, d, c, b, a = d, c, _rotl(b, 30), a, t
    return [(x + y) & 0xffffffff for x, y in zip(state, [a, b, c, d, e])]


def _md_pad(msglen):  # big-endian 64-bit bit-length padding (SHA-1 / SHA-2)
    return b'\x80' + b'\x00' * ((56 - (msglen + 1) % 64) % 64) + struct.pack('>Q', msglen * 8)


def length_extend(algo, orig_hash_hex, orig_msg, append, keylen):
    """Return (forged_message_bytes, new_hash_hex) for the given secret length."""
    nwords = {"sha1": 5, "sha256": 8}[algo]
    block = {"sha1": _sha1_block, "sha256": _sha256_block}[algo]
    state = list(struct.unpack('>%dI' % nwords, bytes.fromhex(orig_hash_hex)))
    glue = _md_pad(keylen + len(orig_msg))
    forged = orig_msg + glue + append
    data = append + _md_pad(keylen + len(forged))
    for i in range(0, len(data), 64):
        state = block(state, data[i:i+64])
    return forged, ''.join('%08x' % x for x in state)


def _parse_bytes(s):
    return bytes.fromhex(s[4:]) if s.startswith("hex:") else s.encode("latin-1")


def lext_cli(algo, orig_hash, msg_s, append_s, keylen_s):
    algo = algo.lower()
    hexlen = {"sha1": 40, "sha256": 64}.get(algo)
    if hexlen is None:
        sys.exit("[-] --lext supports sha1|sha256 natively (md5: use `hashpump`)")
    orig_hash = orig_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{%d}" % hexlen, orig_hash):
        sys.exit(f"[-] {algo} hash must be exactly {hexlen} hex chars (got {len(orig_hash)})")
    try:
        msg, app = _parse_bytes(msg_s), _parse_bytes(append_s)
    except ValueError:
        sys.exit("[-] bad hex: in MSG/APPEND (use hex:DEADBEEF for raw bytes)")
    try:
        if "-" in keylen_s:
            lo, hi = (int(x) for x in keylen_s.split("-", 1)); keys = range(lo, hi + 1)
        else:
            keys = [int(keylen_s)]
    except ValueError:
        sys.exit("[-] KEYLEN must be an int or a 'lo-hi' range")
    if any(k < 0 for k in keys) or (hasattr(keys, "stop") and keys.stop - keys.start > 2000):
        sys.exit("[-] KEYLEN range too large / negative")
    print(f"[*] {algo} length extension - append {app!r} to {msg!r}")
    print("[!] You cannot know keylen without trying it on the server; enumerate the range.\n")
    for k in keys:
        forged, nh = length_extend(algo, orig_hash, msg, app, k)
        print(f"  keylen={k}")
        print(f"    new_hash  : {nh}")
        print(f"    forged_hex: {forged.hex()}")
        print(f"    url_encoded: {quote(forged, safe='')}")


def _iroot(n, k):
    """Exact integer k-th root of n, or None if n is not a perfect k-th power."""
    if n < 0:
        return None
    if n in (0, 1):
        return n
    lo, hi = 1, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo ** k == n else None


def _show_plain(m):
    try:
        b = m.to_bytes((m.bit_length() + 7) // 8, "big")
    except Exception:
        b = str(m).encode()
    print("    [+] plaintext:", b)


def rsa(n, e, c):
    # 1) offline exact e-th root — unpadded ciphertext with small e and m^e < n
    if 0 < e <= 10:
        r = _iroot(c, e)
        if r is not None:
            print(f"[*] exact {e}-th root (no padding, m^e < n):")
            _show_plain(r)
            return

    # 2) factordb (optional; guarded so a missing dep / no network never crashes)
    print(f"[*] factordb {n}")
    try:
        import requests
    except ImportError:
        requests = None
        print("    (python 'requests' not installed: pip install requests — skipping factordb)")
    if requests is not None:
        try:
            j = requests.get(f"http://factordb.com/api?query={n}", timeout=10).json()
            facs = [int(f) for f, _ in j.get("factors", [])]
            print("    status", j.get("status"), "factors", facs)
            if j.get("status") == "FF" and len(facs) >= 2:
                from math import prod
                phi = prod(p - 1 for p in facs)
                try:
                    d = pow(e, -1, phi)
                except ValueError:
                    print("    [-] e not invertible mod phi (gcd(e,phi)!=1) — try per-factor CRT / RsaCtfTool")
                else:
                    _show_plain(pow(c, d, n))
                    return
        except Exception as ex:
            print("    factordb failed:", ex, "(offline? use RsaCtfTool locally)")

    # 3) RsaCtfTool — Wiener, common-modulus, Fermat, Boneh-Durfee, ... (works offline)
    tool = shutil.which("rsactftool") or shutil.which("RsaCtfTool.py")
    if tool:
        print("[*] falling back to RsaCtfTool --attack all")
        _safe(lambda: subprocess.run(
            [tool, "-n", str(n), "-e", str(e), "--uncipher", str(c), "--attack", "all"],
            timeout=int(os.environ.get("TOOL_TIMEOUT") or 120) or None))
    else:
        print("[-] no factorization and no RsaCtfTool on PATH — factor n manually (factordb/Alpertron ECM)")


# ---------------- RSA shared-prime / common-factor GCD ----------------
# If two public moduli share a prime (bad RNG, or recovered from signatures), gcd factors
# both instantly — offline and deterministic. Beats factordb for multi-key challenges.
def rsa_gcd(moduli):
    found = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                found[i] = (g, moduli[i] // g)
            if 1 < g < moduli[j]:
                found[j] = (g, moduli[j] // g)
    return found


def gcd_cli(nums_s):
    try:
        mods = [int(x, 0) for x in nums_s]
    except ValueError:
        sys.exit("[-] --gcd takes integers (decimal or 0x-hex)")
    if len(mods) < 2:
        sys.exit("[-] need >=2 moduli to compare")
    found = rsa_gcd(mods)
    if not found:
        print("[-] no shared prime among the given moduli (they are pairwise coprime)")
        return
    for i, (p, q) in sorted(found.items()):
        print(f"[+] N[{i}] factored:\n    p = {p}\n    q = {q}")
    print("\n[*] now recover each d = inverse(e, (p-1)*(q-1)); m = pow(c, d, N)  (Crypto tab)")


# ---------------- many-time pad / stream-cipher nonce reuse ----------------
# Two+ ciphertexts under the SAME keystream (CTR/stream IV reuse) -> recover plaintexts.
# Frequency-weighted column guessing + crib-anchoring on FLAG_PREFIX. Best-effort: columns
# without a space are ambiguous, so expect ~85-90% and fix the rest by eye.
_FREQ = " etaoinshrdlcumwfgypbvkjxqz"
_FREQW = {c: (len(_FREQ) - i) * 3 for i, c in enumerate(_FREQ)}


def _mtp_score(dec):
    s = 0
    for d in dec:
        ch = chr(d).lower()
        if ch in _FREQW:
            s += _FREQW[ch]
        elif 32 <= d < 127:
            s -= 1
        else:
            s -= 60
    return s


def many_time_pad(cts, crib=b""):
    L = max(len(c) for c in cts)
    ks = [None] * L
    if crib:  # place the crib at the SINGLE most-English anchor (locking every printable
        best = None  # offset over-corrupts the keystream when few ciphertexts exist)
        for c in cts:
            for off in range(len(c) - len(crib) + 1):
                kseg = [c[off + i] ^ crib[i] for i in range(len(crib))]
                chars = [c2[off + i] ^ kseg[i] for c2 in cts
                         for i in range(len(crib)) if off + i < len(c2)]
                if any(not (32 <= d < 127 or d in (9, 10, 13)) for d in chars):
                    continue
                sc = _mtp_score(chars)
                if best is None or sc > best[0]:
                    best = (sc, off, kseg)
        if best:
            _, off, kseg = best
            for i in range(len(crib)):
                ks[off + i] = kseg[i]
    for pos in range(L):
        if ks[pos] is not None:
            continue
        col = [c[pos] for c in cts if pos < len(c)]
        best, bs = 0, -(1 << 30)
        for k in range(256):
            sc = _mtp_score([b ^ k for b in col])
            if sc > bs:
                bs, best = sc, k
        ks[pos] = best
    plains = [bytes(c[i] ^ ks[i] for i in range(len(c))) for c in cts]
    return plains, bytes(ks)


def mtp_cli(cts_hex):
    try:
        cts = [bytes.fromhex(re.sub(r"\s", "", h)) for h in cts_hex]
    except ValueError:
        sys.exit("[-] --mtp takes hex ciphertexts (same length-ish, shared keystream)")
    if len(cts) < 2:
        sys.exit("[-] need >=2 ciphertexts that reuse the keystream")
    crib = next((c.encode() + b"{" for c in (os.environ.get("FLAG_PREFIX") or "").split("|") if c), b"")
    plains, ks = many_time_pad(cts, crib)
    print(f"[*] many-time-pad on {len(cts)} ciphertexts"
          + (f" (crib '{crib.decode()}')" if crib else " (no FLAG_PREFIX crib — set one to anchor)"))
    print("[!] best-effort: space-less columns are ambiguous; fix residual chars by eye.\n")
    print("    keystream(hex):", ks.hex())
    for i, p in enumerate(plains):
        print(f"    pt[{i}]: {p!r}")
        for m in dict.fromkeys(FLAG.findall(p.decode('latin-1', 'ignore'))):
            print(f"      [FLAG] {m}")


def classify(s: str):
    """List EVERY plausible crypto area (a string can fit several) + point to the card."""
    t = s.strip(); hits = []
    if t.startswith("eyJ") and re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", t):
        hits.append("JWT -> crack HS256 secret (jwt_tool -C -d rockyou) or alg:none")
    if "-----BEGIN" in t and "KEY" in t:
        hits.append("RSA/PEM key -> extract n,e; factordb; run with --rsa n e c")
    if re.fullmatch(r"\d{40,}", t):
        hits.append("big integer -> RSA modulus/factor -> factordb; --rsa")
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        L = len(t); h = {32: "MD5/NTLM", 40: "SHA1", 56: "SHA224", 64: "SHA256",
                         96: "SHA384", 128: "SHA512"}.get(L)
        hits.append(f"hex {L} -> {h + ' hash (crack: hashcat/john)' if h else 'hex bytes (xxd -r -p), then re-classify'}")
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) and len(t) % 4 == 0 and re.search(r"[+/=]|(?=.*[a-z])(?=.*[A-Z])", t):
        hits.append("Base64 -> decode (may be layered, or AES/RSA ciphertext underneath)")
    if re.fullmatch(r"[.\-/|\s]+", t) and "." in t and "-" in t:
        hits.append("Morse (.- -...) -> auto-decoded below / dcode.fr Morse")
    if all(c.isalpha() or c.isspace() for c in t) and any(c.isalpha() for c in t):
        hits.append("alphabetic -> classical cipher (Caesar/Atbash/Vigenere/rail-fence auto-tried below; substitution: quipqiup)")
    if len(s) % 16 == 0 and sum(b > 126 or b < 9 for b in s.encode("latin-1", "ignore")) > len(s) * 0.3:
        hits.append("16-byte-aligned high-entropy -> AES/block cipher (ECB/CBC/CTR mode attack)")
    if hits:
        print("[=] LIKELY AREA(S):")
        for h in hits:
            print("    -", h)
    else:
        print("[=] LIKELY AREA: unknown -> see the decode recursion below / try ciphey")
    print()


def selftest():
    """Verify the core engines against known-good references. Exit 0 = all pass."""
    import hashlib
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")

    for algo, hf in (("sha1", hashlib.sha1), ("sha256", hashlib.sha256)):
        sec, orig, app = b"secretKEY123", b"a=1&role=user", b"&role=admin"
        h = hf(sec + orig).hexdigest()
        forged, nh = length_extend(algo, h, orig, app, len(sec))
        check(f"length_extend {algo}", nh == hf(sec + forged).hexdigest())

    check("b64 strict decode", try_decodes(base64.b64encode(b"CSG{x}")).get("b64") == b"CSG{x}")
    check("b64 rejects plain word", _dec_b64("Hello world this is plain") is None)
    check("hex decode", try_decodes(b"43534721").get("hex") == b"CSG!")
    os.environ.setdefault("FLAG_PREFIX", "CSG")   # XOR brute requires a concrete prefix
    check("single-byte xor finds flag",
          any(k.startswith("xor0x") for k in try_decodes(bytes(b ^ 0x5a for b in b"CSG{x}"))))
    check("iroot cube", _iroot(27, 3) == 3 and _iroot(28, 3) is None)

    # rsa shared-prime gcd
    P = 0xf90d8169b0c3b6fcb5b9e0a6e2c7d4e3f1a2b3c4d5e6f70819a2b3c4d5e6f701
    Q1 = 0xc5f3a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d81
    Q2 = 0xb17f2e3d4c5b6a798899aabbccddeeff00112233445566778899aabbccddee03
    g = rsa_gcd([P * Q1, P * Q2]).get(0, (0,))[0]
    check("rsa shared-prime gcd", g > 1 and (P * Q1) % g == 0 and (P * Q2) % g == 0)

    # many-time pad: crib region must be exact + high overall accuracy
    _pts = [b"the meeting is at noon tomorrow okay then", b"please bring the documents with you today!",
            b"i will send the flag CTF{reuse_breaks_ctr}", b"never reuse a keystream in real life people",
            b"attack at dawn and bring the coffee for all", b"many time pad is broken by simple statistics",
            b"the quick brown fox jumps over the lazy dogs", b"cryptography is fun until you reuse a nonce!",
            b"we should always use a fresh random iv value", b"this is another english sentence for testing",
            b"stream ciphers need unique nonces every time", b"security engineering requires careful review"]
    _ks = bytes((i * 137 + 11) & 0xff for i in range(50))
    _cts = [bytes(p[i] ^ _ks[i] for i in range(len(p))) for p in _pts]
    _pl, _ = many_time_pad(_cts, b"CTF{")
    _acc = sum(a[i] == b[i] for a, b in zip(_pl, _pts) for i in range(len(b))) / sum(len(b) for b in _pts)
    check(f"many-time-pad recovery ({_acc:.0%})", b"CTF{" in _pl[2] and _acc > 0.8)

    # classical ciphers (FLAG_PREFIX already set above, so brute ciphers are enabled)
    check("morse decode", try_decodes(b"... --- ...").get("morse") == b"SOS")
    check("atbash", try_decodes(b"svool").get("atbash") == b"hello")

    def _renc(t, rails):
        rows = [''] * rails; r, dd = 0, 1
        for ch in t:
            rows[r] += ch
            dd = 1 if r == 0 else -1 if r == rails - 1 else dd
            r += dd
        return ''.join(rows)

    _pt = "picoCTF{rails}"
    check("rail-fence brute", any(v == _pt.encode() for v in try_decodes(_renc(_pt, 3).encode()).values()))

    def _venc(t, key):
        ki, o = 0, []
        for c in t:
            if c.isalpha():
                b = 65 if c.isupper() else 97
                o.append(chr((ord(c) - b + (ord(key[ki % len(key)]) - 97)) % 26 + b)); ki += 1
            else:
                o.append(c)
        return ''.join(o)

    # chi-square needs enough text per key-column, so use a longer english sample
    _msg = ("the quick brown fox jumps over the lazy dog while the secret message is read aloud "
            "in the quiet room and everyone listens carefully to the words that follow here now "
            "the hidden flag you have been seeking all along is picoCTF{vigenere_frequency} and "
            "you should write it down somewhere safe before you forget the important details ok")
    _vg = [v.decode("latin-1", "ignore") for k, v in try_decodes(_venc(_msg, "lemon").encode()).items()
           if k.startswith("vig")]
    _best = max((sum(a == b for a, b in zip(v, _msg)) / len(_msg) for v in _vg), default=0)
    check(f"vigenere auto ({_best:.0%})", _best > 0.9)

    print("SELFTEST:", "ALL PASS" if ok else "FAILURES ABOVE")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    args = sys.argv[1:] or input("[?] text (or: --rsa n e c | --lext ... | --selftest): ").split()
    if args and args[0] == "--selftest":
        selftest()
    elif args and args[0] == "--gcd":
        gcd_cli(args[1:])
    elif args and args[0] == "--mtp":
        mtp_cli(args[1:])
    elif args and args[0] == "--lext":
        if len(args) != 6:
            sys.exit("usage: --lext sha1|sha256 ORIG_HASH MSG APPEND KEYLEN|lo-hi")
        lext_cli(*args[1:])
    elif len(args) >= 4 and args[0] == "--rsa":
        rsa(int(args[1]), int(args[2]), int(args[3]))
    elif args and args[0] != "--rsa":
        classify(args[0])
        recurse(args[0].encode())
        if shutil.which("ciphey"):
            print("\n[*] ciphey fallback:")
            subprocess.run(["ciphey", "-t", args[0], "-q"])
    else:
        sys.exit(__doc__)
