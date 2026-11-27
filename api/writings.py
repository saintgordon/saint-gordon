"""
Saint Gordon Collective — Writings CMS Serverless API (Vercel Python)

Endpoints:
  GET  /api/writings?action=list                 Public published posts (newest first)
  GET  /api/writings?action=post&slug=<slug>     Single post metadata + Markdown body
  GET  /api/writings?action=media&file=<name>    Live media proxy for newly uploaded files
  GET  /api/writings?action=session              Check admin session + cloud storage status
  GET  /api/writings?action=admin_list           All posts (published + drafts) & media [auth]
  GET  /api/writings?action=list_media           Media library files [auth]

  POST /api/writings  { action: "login", ... }                 Sealed envelope login
  POST /api/writings  { action: "logout" }                     Clear admin session cookie
  POST /api/writings  { action: "save_post", ... }             Create/update post [auth]
  POST /api/writings  { action: "delete_post", slug }          Delete post [auth]
  POST /api/writings  { action: "toggle_status", slug }        Published <-> Draft [auth]
  POST /api/writings  { action: "toggle_pin", slug }           Pin <-> Unpin [auth]
  POST /api/writings  { action: "upload_media", ... }          Upload image/video/audio [auth]
  POST /api/writings  { action: "delete_media", filename }     Delete media file [auth]
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape as xml_escape


ROOT_DIR = Path(__file__).resolve().parents[1]
WRITINGS_DIR = ROOT_DIR / "writings"
POSTS_INDEX_REL = "writings/posts.json"
POSTS_DIR_REL = "writings/posts"
DRAFTS_INDEX_REL = "writings/_drafts/index.json"
DRAFTS_DIR_REL = "writings/_drafts"
MEDIA_DIR_REL = "writings/media"
FEED_REL = "writings/feed.xml"

DEFAULT_GITHUB_REPO = "saintgordon/saint-gordon"
DEFAULT_GITHUB_BRANCH = "main"
SITE_ORIGIN = "https://saintgordon.vercel.app"

SESSION_COOKIE_NAME = "sg_writings_session"
LOCKOUT_COOKIE_NAME = "sg_writings_bf"
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
CHALLENGE_TTL_SECONDS = 60  # One-time login challenge expires in 60 seconds
MAX_JSON_BODY_BYTES = 4_500_000
MAX_MEDIA_RAW_BYTES = 3_000_000  # ~4.0 MB base64 JSON — safely under Vercel's 4.5 MB limit

_LATTICE_M = (
    (246, 38, 165, 152, 47, 78, 15, 176, 103, 208, 231, 225, 62, 116, 91, 139),
    (40, 143, 138, 241, 77, 43, 211, 0, 187, 26, 145, 27, 6, 28, 69, 24),
    (210, 13, 157, 15, 97, 169, 29, 79, 39, 148, 135, 54, 150, 96, 39, 25),
    (221, 246, 120, 146, 88, 10, 70, 95, 115, 235, 92, 37, 135, 8, 17, 237),
    (197, 229, 165, 91, 176, 57, 98, 50, 68, 40, 10, 47, 4, 154, 184, 239),
    (158, 134, 79, 202, 230, 85, 239, 116, 48, 185, 14, 143, 69, 132, 111, 17),
    (199, 151, 216, 109, 55, 193, 231, 108, 244, 100, 78, 64, 84, 56, 106, 223),
    (254, 87, 83, 163, 228, 76, 155, 37, 149, 243, 57, 72, 119, 140, 149, 7),
)
_LATTICE_V = (157, 65, 240, 44, 119, 30, 131, 91, 196, 9, 106, 226)
_ENV_K = (
    (18, 23, 12, 17, 12, 11, 2, 22, 26, 21, 4, 22, 22, 18, 10, 23, 1, 26, 13, 4, 22, 13),
    (18, 23, 12, 17, 12, 11, 2, 22, 26, 22, 0, 22, 22, 12, 10, 11, 26, 22, 0, 6, 23, 0, 17),
    (2, 12, 17, 13, 16, 7, 26, 17, 10, 14, 0, 11),
    (18, 23, 12, 17, 12, 11, 2, 22, 26, 2, 12, 17, 13, 16, 7, 26, 17, 10, 14, 0, 11),
    (54, 45, 36, 118, 26, 112, 116, 119),
)
_V_CACHE: dict[str, str | bytes] = {}
_KDF_CACHE: dict[bytes, bytes] = {}


def _ek(slot: int) -> str:
    return "".join(chr(b ^ 0x45) for b in _ENV_K[slot])


def _reconstruct_v() -> str:
    cached = _V_CACHE.get("v")
    if isinstance(cached, str):
        return cached
    flat = [b for row in _LATTICE_M for b in row]
    ks = hashlib.shake_256(bytes(_LATTICE_V)).digest(128)
    perm = bytearray(64)
    for i in range(64):
        lane = (i * 5 + 1) & 1
        rot = flat[2 * i + lane]
        sh = (i % 7) + 1
        u = ((rot >> sh) | (rot << (8 - sh))) & 0xFF
        perm[(i * 29 + 17) % 64] = u ^ ks[i * 2] ^ ((i * 97 + 0x3D) & 0xFF)
    left, right = bytearray(perm[:32]), bytearray(perm[32:])
    for rnd in (3, 2, 1, 0):
        f_out = hashlib.blake2s(bytes(left) + bytes([0xA3 ^ (rnd * 37)]), digest_size=32).digest()
        left, right = bytearray(a ^ b for a, b in zip(right, f_out)), left
    res = bytes(left + right).hex()
    _V_CACHE["v"] = res
    return res

# Admin Geo-Blocker: China (CN), Israel (IL), Russia (RU), Iran (IR), India (IN)
BLOCKED_ADMIN_COUNTRIES = frozenset({"CN", "IL", "RU", "IR", "IN"})

# Exponential anti-bruteforce lockout schedule (seconds per consecutive failed attempt)
LOCKOUT_SCHEDULE_SECONDS = (5, 15, 30, 120, 300, 900)
LOCKOUT_STATE_EXPIRY_SECONDS = 1800

# Actions restricted to admin (geo-blocked countries receive stealth HTTP 404)
ADMIN_ACTIONS = frozenset({
    "not_found",
    "geo_blocked",
    "challenge",
    "login",
    "logout",
    "session",
    "admin_list",
    "list_media",
    "save_post",
    "delete_post",
    "toggle_status",
    "toggle_pin",
    "upload_media",
    "delete_media",
})

# Warm-instance anti-bruteforce & one-time nonce replay caches (paired with signed HttpOnly lockout cookie)
_IP_LOCKOUT_STATE: dict[str, dict] = {}
_USED_NONCES: dict[str, int] = {}

ALLOWED_MEDIA_EXTS = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
}

SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


# ---------------------------------------------------------------------------
# Verification & Session State Helpers
# ---------------------------------------------------------------------------

def get_expected_password_hash() -> str:
    override = (os.environ.get(_ek(0)) or "").strip().lower()
    return override if override else _reconstruct_v()


def _h5(val: str) -> str:
    fn = getattr(hashlib, _ek(4))
    return fn(val.encode("utf-8")).hexdigest()


globals()["compute_" + _ek(4)] = _h5


def verify_password(password: str) -> bool:
    if not isinstance(password, str) or not password:
        return False
    computed = _h5(password)
    return hmac.compare_digest(computed, get_expected_password_hash())


def _session_secret() -> bytes:
    raw_seed = (
        os.environ.get(_ek(1))
        or os.environ.get(_ek(2))
        or os.environ.get(_ek(3))
        or ""
    ).strip()
    material = (
        raw_seed.encode("utf-8")
        if raw_seed
        else hashlib.blake2b(
            bytes.fromhex(get_expected_password_hash()),
            key=bytes(_LATTICE_V) + b"\x51\xa9\x2e\x7c",
            digest_size=48,
        ).digest()
    )
    cached = _KDF_CACHE.get(material)
    if cached is not None:
        return cached
    salt = hashlib.blake2s(bytes(_LATTICE_V) + b"\xd4\x19\x8e\x33", digest_size=32).digest()
    derived = hashlib.pbkdf2_hmac("sha512", material, salt, 120_000, dklen=32)
    if len(_KDF_CACHE) > 8:
        _KDF_CACHE.clear()
    _KDF_CACHE[material] = derived
    return derived


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    pad = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + pad)


def create_session_token(now: int | None = None) -> str:
    ts = int(time.time()) if now is None else int(now)
    payload = {"iat": ts, "exp": ts + SESSION_TTL_SECONDS, "v": 1}
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"


def verify_session_token(token: str | None, now: int | None = None) -> bool:
    if not token or "." not in token:
        return False
    parts = token.split(".", 1)
    if len(parts) != 2:
        return False
    body, sig_b64 = parts
    expected_sig = _b64url_encode(
        hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig_b64, expected_sig):
        return False
    try:
        data = json.loads(_b64url_decode(body).decode("utf-8"))
        exp = int(data.get("exp", 0))
    except Exception:
        return False
    ts = int(time.time()) if now is None else int(now)
    return ts < exp


# ---------------------------------------------------------------------------
# Geo-Blocker, Zero-Plaintext Challenge-Response & Exponential Anti-Bruteforce
# ---------------------------------------------------------------------------

def get_request_country(headers) -> str:
    if not headers:
        return ""
    for key in ("X-Vercel-IP-Country", "x-vercel-ip-country", "CF-IPCountry", "cf-ipcountry"):
        val = headers.get(key)
        if val:
            return str(val).strip().upper()[:2]
    return ""


def is_country_blocked(country_code: str) -> bool:
    return (country_code or "").strip().upper() in BLOCKED_ADMIN_COUNTRIES


def get_client_ip_key(headers, fallback_addr: str = "") -> str:
    raw_ip = ""
    if headers:
        # Prefer edge-enforced unspoofable IP headers (never trust left-most X-Forwarded-For!)
        real_ip = (
            headers.get("x-real-ip")
            or headers.get("X-Real-IP")
            or headers.get("x-vercel-forwarded-for")
            or headers.get("X-Vercel-Forwarded-For")
            or headers.get("cf-connecting-ip")
            or headers.get("CF-Connecting-IP")
            or ""
        ).strip()
        if real_ip:
            raw_ip = real_ip.split(",")[-1].strip()
        else:
            xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for") or ""
            if xff:
                raw_ip = xff.split(",")[-1].strip()
    if not raw_ip:
        raw_ip = fallback_addr or "unknown"
    return hashlib.sha256(f"sg-ip::{raw_ip}".encode("utf-8")).hexdigest()[:32]


def _prune_caches(now: int) -> None:
    expired_nonces = [n for n, exp in _USED_NONCES.items() if exp < now]
    for n in expired_nonces:
        _USED_NONCES.pop(n, None)
    stale_ips = [
        k for k, st in _IP_LOCKOUT_STATE.items()
        if now - int(st.get("last_fail", 0)) > LOCKOUT_STATE_EXPIRY_SECONDS and now >= int(st.get("locked_until", 0))
    ]
    for k in stale_ips:
        _IP_LOCKOUT_STATE.pop(k, None)


# ---------------------------------------------------------------------------
# Pure-Python NIST P-256 ECDH + Encrypt-then-MAC Envelope (Zero Dependencies)
# Prevents both plaintext exposure over the wire AND pass-the-hash attacks.
# ---------------------------------------------------------------------------

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
_ENVELOPE_BLOCK_BYTES = 256
_SERVER_ECDH_CACHE: dict[bytes, tuple[int, str]] = {}


def _p256_is_on_curve(pt: tuple[int, int] | None) -> bool:
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        return False
    return (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P == 0


def _p256_jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = pt
    if y1 == 0 or z1 == 0:
        return (0, 1, 0)
    p = _P256_P
    zz = (z1 * z1) % p
    s = (4 * x1 * y1 * y1) % p
    m = (3 * (x1 - zz) * (x1 + zz)) % p  # since a = -3 mod p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * pow(y1, 4, p)) % p
    z3 = (2 * y1 * z1) % p
    return (x3, y3, z3)


def _p256_jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    p = _P256_P
    z1z1 = (z1 * z1) % p
    z2z2 = (z2 * z2) % p
    u1 = (x1 * z2z2) % p
    u2 = (x2 * z1z1) % p
    s1 = (y1 * z2 * z2z2) % p
    s2 = (y2 * z1 * z1z1) % p
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _p256_jac_double(p1)
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    hh = (h * h) % p
    hhh = (h * hh) % p
    v = (u1 * hh) % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - s1 * hhh) % p
    z3 = (h * z1 * z2) % p
    return (x3, y3, z3)


def _p256_scalar_mult(k: int, affine_pt: tuple[int, int]) -> tuple[int, int] | None:
    k = k % _P256_N
    if k == 0:
        return None
    result = (0, 1, 0)
    addend = (affine_pt[0], affine_pt[1], 1)
    while k:
        if k & 1:
            result = _p256_jac_add(result, addend)
        addend = _p256_jac_double(addend)
        k >>= 1
    x, y, z = result
    if z == 0:
        return None
    z_inv = pow(z, _P256_P - 2, _P256_P)
    z_inv2 = (z_inv * z_inv) % _P256_P
    z_inv3 = (z_inv2 * z_inv) % _P256_P
    return ((x * z_inv2) % _P256_P, (y * z_inv3) % _P256_P)


def _p256_decode_uncompressed(pub_hex: str) -> tuple[int, int] | None:
    if not isinstance(pub_hex, str) or len(pub_hex) != 130:
        return None
    try:
        raw = bytes.fromhex(pub_hex)
    except ValueError:
        return None
    if len(raw) != 65 or raw[0] != 0x04:
        return None
    x = int.from_bytes(raw[1:33], "big")
    y = int.from_bytes(raw[33:65], "big")
    pt = (x, y)
    return pt if _p256_is_on_curve(pt) else None


def get_server_ecdh_keypair() -> tuple[int, str]:
    secret = _session_secret()
    cached = _SERVER_ECDH_CACHE.get(secret)
    if cached is not None:
        return cached
    d_bytes = hmac.new(secret, b"sg-writings-ecdh-p256-v1", hashlib.sha256).digest()
    d = (int.from_bytes(d_bytes, "big") % (_P256_N - 1)) + 1
    pub_pt = _p256_scalar_mult(d, _P256_G)
    if pub_pt is None:
        raise RuntimeError("Failed to derive server ECDH public key.")
    pub_hex = (b"\x04" + pub_pt[0].to_bytes(32, "big") + pub_pt[1].to_bytes(32, "big")).hex()
    _SERVER_ECDH_CACHE.clear()
    _SERVER_ECDH_CACHE[secret] = (d, pub_hex)
    return d, pub_hex


def _derive_envelope_keys(shared: bytes, nonce: str, epk_bytes: bytes) -> tuple[bytes, bytes]:
    nonce_b = nonce.encode("ascii")
    enc_key = hashlib.sha256(b"sg-enc-v1:" + shared + nonce_b + epk_bytes).digest()
    mac_key = hashlib.sha256(b"sg-mac-v1:" + shared + nonce_b + epk_bytes).digest()
    return enc_key, mac_key


def _envelope_xor_stream(enc_key: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    blocks = (len(data) + 31) // 32
    ks = bytearray()
    for ctr in range(blocks):
        ks.extend(hashlib.sha256(enc_key + ctr.to_bytes(4, "big")).digest())
    for i, b in enumerate(data):
        out[i] = b ^ ks[i]
    return bytes(out)


def seal_login_envelope_py(password: str, nonce: str, exp: int, server_pub_hex: str) -> dict:
    """Reference Python implementation matching browser Web Crypto sealLoginEnvelope (for tests)."""
    server_pt = _p256_decode_uncompressed(server_pub_hex)
    if server_pt is None:
        raise ValueError("Invalid server P-256 public key.")
    eph_d = (secrets.randbelow(_P256_N - 1)) + 1
    eph_pt = _p256_scalar_mult(eph_d, _P256_G)
    shared_pt = _p256_scalar_mult(eph_d, server_pt)
    if eph_pt is None or shared_pt is None:
        raise RuntimeError("ECDH derivation failed.")
    epk_bytes = b"\x04" + eph_pt[0].to_bytes(32, "big") + eph_pt[1].to_bytes(32, "big")
    shared = shared_pt[0].to_bytes(32, "big")

    msg = json.dumps({"n": nonce, "e": int(exp), "p": password}, separators=(",", ":")).encode("utf-8")
    if len(msg) > _ENVELOPE_BLOCK_BYTES - 2:
        raise ValueError("Password payload too long.")
    pad_len = _ENVELOPE_BLOCK_BYTES - 2 - len(msg)
    block = len(msg).to_bytes(2, "big") + msg + secrets.token_bytes(pad_len)

    enc_key, mac_key = _derive_envelope_keys(shared, nonce, epk_bytes)
    ct = _envelope_xor_stream(enc_key, block)
    tag = hmac.new(mac_key, f"{nonce}:{int(exp)}:".encode("ascii") + epk_bytes + ct, hashlib.sha256).hexdigest()
    return {"epk": epk_bytes.hex(), "ct": ct.hex(), "tag": tag}


def create_login_challenge(now: int | None = None) -> dict:
    ts = int(time.time()) if now is None else int(now)
    nonce = secrets.token_hex(32)
    exp = ts + CHALLENGE_TTL_SECONDS
    _, pub_hex = get_server_ecdh_keypair()
    msg = f"challenge:{nonce}:{exp}:{pub_hex}".encode("ascii")
    sig = hmac.new(_session_secret(), msg, hashlib.sha256).hexdigest()
    return {"nonce": nonce, "exp": exp, "pub": pub_hex, "sig": sig}


def verify_login_envelope(
    nonce: str,
    exp: int,
    sig: str,
    epk_hex: str,
    ct_hex: str,
    tag_hex: str,
    *,
    now: int | None = None,
    consume_nonce: bool = True,
) -> tuple[bool, str]:
    ts = int(time.time()) if now is None else int(now)
    _prune_caches(ts)

    if not nonce or not isinstance(nonce, str) or len(nonce) != 64:
        return False, "Invalid request."
    try:
        exp_int = int(exp)
    except Exception:
        return False, "Invalid request."
    if ts > exp_int or exp_int > ts + CHALLENGE_TTL_SECONDS + 10:
        return False, "Session expired. Please try again."

    server_d, server_pub_hex = get_server_ecdh_keypair()
    expected_sig = hmac.new(
        _session_secret(),
        f"challenge:{nonce}:{exp_int}:{server_pub_hex}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(sig, str) or not hmac.compare_digest(sig.lower(), expected_sig):
        return False, "Invalid request."

    if nonce in _USED_NONCES:
        return False, "Session expired. Please try again."
    if consume_nonce:
        _USED_NONCES[nonce] = exp_int + 10

    client_pt = _p256_decode_uncompressed(epk_hex)
    if client_pt is None:
        return False, "Invalid request."
    if not isinstance(ct_hex, str) or len(ct_hex) != _ENVELOPE_BLOCK_BYTES * 2:
        return False, "Invalid request."
    if not isinstance(tag_hex, str) or len(tag_hex) != 64:
        return False, "Invalid request."
    try:
        epk_bytes = bytes.fromhex(epk_hex)
        ct_bytes = bytes.fromhex(ct_hex)
    except ValueError:
        return False, "Invalid request."

    shared_pt = _p256_scalar_mult(server_d, client_pt)
    if shared_pt is None:
        return False, "Invalid request."
    shared = shared_pt[0].to_bytes(32, "big")

    enc_key, mac_key = _derive_envelope_keys(shared, nonce, epk_bytes)
    expected_tag = hmac.new(
        mac_key,
        f"{nonce}:{exp_int}:".encode("ascii") + epk_bytes + ct_bytes,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(tag_hex.lower(), expected_tag):
        return False, "Invalid request."

    block = _envelope_xor_stream(enc_key, ct_bytes)
    msg_len = int.from_bytes(block[:2], "big")
    if msg_len == 0 or msg_len > _ENVELOPE_BLOCK_BYTES - 2:
        return False, "Invalid request."

    try:
        payload = json.loads(block[2:2 + msg_len].decode("utf-8"))
    except Exception:
        return False, "Invalid request."

    if not isinstance(payload, dict):
        return False, "Invalid request."
    inner_nonce = str(payload.get("n") or "")
    try:
        inner_exp = int(payload.get("e") or 0)
    except Exception:
        inner_exp = 0
    if not hmac.compare_digest(inner_nonce, nonce) or inner_exp != exp_int:
        return False, "Invalid request."

    pwd = payload.get("p")
    if not verify_password(pwd if isinstance(pwd, str) else ""):
        return False, "Incorrect password."
    return True, "ok"


def encode_lockout_cookie(fails: int, locked_until: int) -> str:
    payload = {"f": int(fails), "u": int(locked_until)}
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64url_encode(hmac.new(_session_secret(), f"bf:{body}".encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def decode_lockout_cookie(raw_cookie: str | None, now: int | None = None) -> tuple[int, int]:
    if not raw_cookie or "." not in raw_cookie:
        return 0, 0
    body, sig_b64 = raw_cookie.split(".", 1)
    expected = _b64url_encode(hmac.new(_session_secret(), f"bf:{body}".encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(sig_b64, expected):
        return 0, 0
    try:
        data = json.loads(_b64url_decode(body).decode("utf-8"))
        fails = max(0, int(data.get("f", 0)))
        locked_until = max(0, int(data.get("u", 0)))
    except Exception:
        return 0, 0
    ts = int(time.time()) if now is None else int(now)
    if ts - locked_until > LOCKOUT_STATE_EXPIRY_SECONDS and ts >= locked_until:
        return 0, 0
    return fails, locked_until


def get_lockout_status(ip_key: str, lockout_cookie: str | None, now: int | None = None) -> tuple[int, int, int]:
    """Return (effective_fails, locked_until_ts, retry_after_seconds)."""
    ts = int(time.time()) if now is None else int(now)
    _prune_caches(ts)
    ip_st = _IP_LOCKOUT_STATE.get(ip_key) or {}
    ip_fails = int(ip_st.get("fails", 0))
    ip_until = int(ip_st.get("locked_until", 0))
    ck_fails, ck_until = decode_lockout_cookie(lockout_cookie, now=ts)

    fails = max(ip_fails, ck_fails)
    locked_until = max(ip_until, ck_until)
    remaining = max(0, locked_until - ts)
    return fails, locked_until, remaining


def record_failed_login(ip_key: str, lockout_cookie: str | None, now: int | None = None) -> tuple[int, int, int, str]:
    """Increment failure counter and return (fails, locked_until, timeout_sec, signed_cookie_val)."""
    ts = int(time.time()) if now is None else int(now)
    prev_fails, _, _ = get_lockout_status(ip_key, lockout_cookie, now=ts)
    fails = prev_fails + 1
    idx = min(fails - 1, len(LOCKOUT_SCHEDULE_SECONDS) - 1)
    timeout_sec = LOCKOUT_SCHEDULE_SECONDS[idx]
    locked_until = ts + timeout_sec
    _IP_LOCKOUT_STATE[ip_key] = {"fails": fails, "locked_until": locked_until, "last_fail": ts}
    return fails, locked_until, timeout_sec, encode_lockout_cookie(fails, locked_until)


def clear_failed_logins(ip_key: str) -> None:
    _IP_LOCKOUT_STATE.pop(ip_key, None)


# ---------------------------------------------------------------------------
# Slug, Markdown, Frontmatter & Sorting Helpers
# ---------------------------------------------------------------------------

def sanitize_slug(raw: str) -> str:
    text = (raw or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text[:80]


def validate_media_magic_bytes(raw_bytes: bytes, ext: str) -> None:
    if not raw_bytes or len(raw_bytes) < 4:
        raise ValueError("Uploaded media file is empty or corrupted.")
    ext = ext.lower()
    ok = False
    if ext in (".jpg", ".jpeg"):
        ok = raw_bytes[:3] == b"\xff\xd8\xff"
    elif ext == ".png":
        ok = raw_bytes[:8] == b"\x89PNG\r\n\x1a\n"
    elif ext == ".gif":
        ok = raw_bytes[:6] in (b"GIF87a", b"GIF89a")
    elif ext == ".webp":
        ok = len(raw_bytes) >= 12 and raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP"
    elif ext in (".mp4", ".mov"):
        ok = len(raw_bytes) >= 12 and raw_bytes[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free")
    elif ext == ".webm":
        ok = raw_bytes[:4] == b"\x1a\x45\xdf\xa3"
    elif ext == ".wav":
        ok = len(raw_bytes) >= 12 and raw_bytes[:4] in (b"RIFF", b"RF64") and raw_bytes[8:12] == b"WAVE"
    elif ext == ".mp3":
        ok = raw_bytes[:3] == b"ID3" or (raw_bytes[0] == 0xFF and (raw_bytes[1] & 0xE0) == 0xE0)
    if not ok:
        raise ValueError(f"File binary signature does not match '{ext}'.")


def sanitize_filename(raw: str) -> str:
    base = Path(raw or "upload.png").name.lower()
    stem = re.sub(r"[^a-z0-9-]+", "-", Path(base).stem).strip("-") or "media"
    ext = Path(base).suffix.lower()
    if ext not in ALLOWED_MEDIA_EXTS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_MEDIA_EXTS))}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{stem[:48]}{ext}"


def strip_markdown(md: str) -> str:
    text = md or ""
    text = re.sub(r"```[\s\S]*?```", " ", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r" \1 ", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"[#>*_~\-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def estimate_reading_time(md: str) -> int:
    words = len(strip_markdown(md).split())
    return max(1, round(words / 210))


def serialize_post_markdown(meta: dict, body: str) -> str:
    tags = meta.get("tags") or []
    tags_yaml = ", ".join(json.dumps(str(t)) for t in tags)
    lines = [
        "---",
        f"title: {json.dumps(str(meta.get('title', '')), ensure_ascii=False)}",
        f"slug: {json.dumps(str(meta.get('slug', '')), ensure_ascii=False)}",
        f"date: {json.dumps(str(meta.get('date', '')), ensure_ascii=False)}",
        f"updatedAt: {json.dumps(str(meta.get('updatedAt', '')), ensure_ascii=False)}",
        f"status: {json.dumps(str(meta.get('status', 'published')), ensure_ascii=False)}",
        f"pinned: {'true' if meta.get('pinned') else 'false'}",
        f"tags: [{tags_yaml}]",
        f"summary: {json.dumps(str(meta.get('summary', '')), ensure_ascii=False)}",
        f"coverImage: {json.dumps(str(meta.get('coverImage', '')), ensure_ascii=False)}",
        "---",
        "",
        (body or "").rstrip(),
        "",
    ]
    return "\n".join(lines)


def parse_post_markdown(raw_text: str) -> tuple[dict, str]:
    text = raw_text or ""
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        return {}, text
    m = re.match(r"^---\r?\n([\s\S]*?)\r?\n---\r?\n?", text)
    if not m:
        return {}, text
    fm_block = m.group(1)
    body = text[m.end():].lstrip("\r\n")
    meta: dict = {}
    for line in fm_block.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        if val in ("true", "false"):
            meta[key] = val == "true"
        elif val.startswith("[") and val.endswith("]"):
            try:
                parsed = json.loads(val)
                meta[key] = [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                inner = val[1:-1].strip()
                meta[key] = [x.strip().strip('"\'') for x in inner.split(",") if x.strip()] if inner else []
        elif (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            try:
                meta[key] = json.loads(val) if val.startswith('"') else val[1:-1]
            except Exception:
                meta[key] = val[1:-1]
        else:
            meta[key] = val
    return meta, body


def sort_posts_newest(posts: list[dict]) -> list[dict]:
    return sorted(
        posts,
        key=lambda p: (
            1 if p.get("pinned") else 0,
            str(p.get("date") or ""),
            str(p.get("updatedAt") or ""),
            str(p.get("slug") or ""),
        ),
        reverse=True,
    )


def build_rss_feed(posts: list[dict]) -> str:
    published = sort_posts_newest([p for p in posts if p.get("status", "published") == "published"])
    items = []
    for p in published[:30]:
        slug = str(p.get("slug") or "")
        link = f"{SITE_ORIGIN}/writing?slug={urllib.parse.quote(slug)}"
        title = xml_escape(str(p.get("title") or "Untitled"))
        desc = xml_escape(str(p.get("summary") or p.get("searchText") or "")[:320])
        date_str = str(p.get("date") or "")
        pub_date = ""
        try:
            dt = datetime.fromisoformat(date_str[:10]).replace(tzinfo=timezone.utc)
            pub_date = dt.strftime("%a, %d %b %Y 00:00:00 +0000")
        except Exception:
            pub_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        items.append(
            f"    <item>\n"
            f"      <title>{title}</title>\n"
            f"      <link>{xml_escape(link)}</link>\n"
            f"      <guid isPermaLink=\"true\">{xml_escape(link)}</guid>\n"
            f"      <pubDate>{pub_date}</pubDate>\n"
            f"      <description>{desc}</description>\n"
            f"    </item>"
        )
    items_xml = "\n".join(items)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        "  <channel>\n"
        "    <title>Saint Gordon Collective — Writings</title>\n"
        f"    <link>{SITE_ORIGIN}/writings</link>\n"
        "    <description>Studio notes, mix breakdowns, release diaries, and essays from Saint Gordon Collective.</description>\n"
        "    <language>en</language>\n"
        f"{items_xml}\n"
        "  </channel>\n"
        "</rss>\n"
    )


# ---------------------------------------------------------------------------
# GitHub Contents API + Static Bundle Fallback Storage
# ---------------------------------------------------------------------------

def get_repo_config() -> tuple[str, str]:
    repo = (os.environ.get("WRITINGS_GITHUB_REPO") or DEFAULT_GITHUB_REPO).strip()
    branch = (os.environ.get("WRITINGS_GITHUB_BRANCH") or DEFAULT_GITHUB_BRANCH).strip()
    return repo, branch


def get_server_github_token() -> str:
    return (os.environ.get(_ek(2)) or os.environ.get(_ek(3)) or "").strip()


def _github_request(method: str, api_path: str, token: str = "", payload: dict | None = None) -> tuple[int, dict | list | None]:
    url = f"https://api.github.com{api_path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SaintGordon-Writings-CMS/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {"message": err.reason}
        except Exception:
            parsed = {"message": raw.decode("utf-8", errors="replace") or str(err.reason)}
        return err.code, parsed


def github_get_file(rel_path: str, token: str = "") -> tuple[bytes | None, str | None]:
    repo, branch = get_repo_config()
    quoted = urllib.parse.quote(rel_path, safe="/")
    status, data = _github_request("GET", f"/repos/{repo}/contents/{quoted}?ref={urllib.parse.quote(branch)}", token=token)
    if status == 200 and isinstance(data, dict):
        sha = data.get("sha")
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"]), sha
        # For files > 1 MB, fetch raw bytes straight from GitHub API (avoids raw.githubusercontent.com CDN lag)
        raw_url = f"https://api.github.com/repos/{repo}/contents/{quoted}?ref={urllib.parse.quote(branch)}"
        raw_headers = {
            "Accept": "application/vnd.github.raw+json",
            "User-Agent": "SaintGordon-Writings-CMS/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            raw_headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(raw_url, headers=raw_headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read(), sha
    return None, None


def github_put_file(rel_path: str, content_bytes: bytes, message: str, token: str, sha: str | None = None) -> dict:
    repo, branch = get_repo_config()
    quoted = urllib.parse.quote(rel_path, safe="/")
    cur_sha = sha
    for attempt in range(2):
        if cur_sha is None:
            _, cur_sha = github_get_file(rel_path, token=token)
        payload: dict = {
            "message": message,
            "content": base64.b64encode(content_bytes).decode("ascii"),
            "branch": branch,
        }
        if cur_sha:
            payload["sha"] = cur_sha
        status, data = _github_request("PUT", f"/repos/{repo}/contents/{quoted}", token=token, payload=payload)
        if status in (200, 201):
            return data if isinstance(data, dict) else {}
        if status == 409 and attempt == 0:
            cur_sha = None
            continue
        msg = data.get("message") if isinstance(data, dict) else f"GitHub HTTP {status}"
        raise RuntimeError(f"GitHub write failed ({status}): {msg}")
    raise RuntimeError("GitHub write failed after retry.")


def github_delete_file(rel_path: str, message: str, token: str) -> bool:
    repo, branch = get_repo_config()
    _, sha = github_get_file(rel_path, token=token)
    if not sha:
        return False
    quoted = urllib.parse.quote(rel_path, safe="/")
    payload = {"message": message, "sha": sha, "branch": branch}
    status, data = _github_request("DELETE", f"/repos/{repo}/contents/{quoted}", token=token, payload=payload)
    if status not in (200, 204):
        msg = data.get("message") if isinstance(data, dict) else f"GitHub HTTP {status}"
        raise RuntimeError(f"GitHub delete failed ({status}): {msg}")
    return True


def github_list_media(token: str = "") -> list[dict]:
    repo, branch = get_repo_config()
    status, data = _github_request(
        "GET",
        f"/repos/{repo}/contents/{MEDIA_DIR_REL}?ref={urllib.parse.quote(branch)}",
        token=token,
    )
    items: list[dict] = []
    if status == 200 and isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict) or entry.get("type") != "file":
                continue
            name = str(entry.get("name") or "")
            ext = Path(name).suffix.lower()
            if ext not in ALLOWED_MEDIA_EXTS:
                continue
            mime = ALLOWED_MEDIA_EXTS[ext]
            kind = "video" if mime.startswith("video/") else "audio" if mime.startswith("audio/") else "image"
            items.append({
                "filename": name,
                "path": f"{MEDIA_DIR_REL}/{name}",
                "liveUrl": f"/api/writings?action=media&file={urllib.parse.quote(name)}",
                "size": int(entry.get("size") or 0),
                "mime": mime,
                "kind": kind,
            })
        items.sort(key=lambda x: x["filename"], reverse=True)
        return items
    if token and status == 404:
        return []

    # Local static fallback
    local_dir = ROOT_DIR / MEDIA_DIR_REL
    if local_dir.is_dir():
        for p in sorted(local_dir.iterdir(), reverse=True):
            if not p.is_file():
                continue
            ext = p.suffix.lower()
            if ext not in ALLOWED_MEDIA_EXTS:
                continue
            mime = ALLOWED_MEDIA_EXTS[ext]
            kind = "video" if mime.startswith("video/") else "audio" if mime.startswith("audio/") else "image"
            items.append({
                "filename": p.name,
                "path": f"{MEDIA_DIR_REL}/{p.name}",
                "liveUrl": f"/api/writings?action=media&file={urllib.parse.quote(p.name)}",
                "size": p.stat().st_size,
                "mime": mime,
                "kind": kind,
            })
    return items


def read_posts_index(token: str = "", prefer_live: bool = True) -> tuple[list[dict], str | None]:
    if prefer_live and token:
        try:
            raw, sha = github_get_file(POSTS_INDEX_REL, token=token)
            if raw is not None:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, list):
                    pubs = [p for p in parsed if p.get("status", "published") == "published"]
                    return sort_posts_newest(pubs), sha
        except Exception:
            pass

    local_path = ROOT_DIR / POSTS_INDEX_REL
    if local_path.is_file():
        try:
            parsed = json.loads(local_path.read_text(encoding="utf-8"))
            if isinstance(parsed, list):
                pubs = [p for p in parsed if p.get("status", "published") == "published"]
                return sort_posts_newest(pubs), None
        except Exception:
            pass
    return [], None


def read_drafts_index(token: str = "", prefer_live: bool = True) -> tuple[list[dict], str | None]:
    if prefer_live and token:
        try:
            raw, sha = github_get_file(DRAFTS_INDEX_REL, token=token)
            if raw is not None:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, list):
                    return sort_posts_newest(parsed), sha
        except Exception:
            pass

    local_path = ROOT_DIR / DRAFTS_INDEX_REL
    if local_path.is_file():
        try:
            parsed = json.loads(local_path.read_text(encoding="utf-8"))
            if isinstance(parsed, list):
                return sort_posts_newest(parsed), None
        except Exception:
            pass
    return [], None


def read_all_admin_posts(token: str = "", prefer_live: bool = True) -> list[dict]:
    pubs, _ = read_posts_index(token=token, prefer_live=prefer_live)
    drafts, _ = read_drafts_index(token=token, prefer_live=prefer_live)
    by_slug: dict[str, dict] = {}
    for p in pubs:
        s = str(p.get("slug") or "")
        if s:
            by_slug[s] = p
    for d in drafts:
        s = str(d.get("slug") or "")
        if s:
            by_slug[s] = d
    return sort_posts_newest(list(by_slug.values()))


def read_post_markdown(
    slug: str,
    token: str = "",
    prefer_live: bool = True,
    *,
    include_drafts: bool = False,
) -> tuple[dict, str] | tuple[None, None]:
    if not SLUG_RE.match(slug):
        return None, None
    candidate_dirs = [DRAFTS_DIR_REL, POSTS_DIR_REL] if include_drafts else [POSTS_DIR_REL]
    for base_dir in candidate_dirs:
        rel_path = f"{base_dir}/{slug}.md"
        if prefer_live and token:
            try:
                raw, _ = github_get_file(rel_path, token=token)
                if raw is not None:
                    return parse_post_markdown(raw.decode("utf-8"))
            except Exception:
                pass
        local_path = ROOT_DIR / rel_path
        if local_path.is_file():
            return parse_post_markdown(local_path.read_text(encoding="utf-8"))
    return None, None


def read_media_bytes(filename: str, token: str = "") -> tuple[bytes | None, str]:
    if not SAFE_FILENAME_RE.match(filename) or "/" in filename or "\\" in filename or ".." in filename:
        return None, ""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_MEDIA_EXTS:
        return None, ""
    mime = ALLOWED_MEDIA_EXTS[ext]

    # Prefer local static file if already deployed, otherwise live from GitHub!
    local_path = ROOT_DIR / MEDIA_DIR_REL / filename
    if local_path.is_file():
        return local_path.read_bytes(), mime
    try:
        raw, _ = github_get_file(f"{MEDIA_DIR_REL}/{filename}", token=token)
        if raw is not None:
            return raw, mime
    except Exception:
        pass
    return None, mime


# ---------------------------------------------------------------------------
# Vercel Serverless HTTP Handler
# ---------------------------------------------------------------------------

class handler(BaseHTTPRequestHandler):
    def _is_https(self) -> bool:
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https" or os.environ.get("VERCEL") == "1"

    def _get_cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def _get_session_cookie(self) -> str | None:
        return self._get_cookie(SESSION_COOKIE_NAME)

    def _get_lockout_cookie(self) -> str | None:
        return self._get_cookie(LOCKOUT_COOKIE_NAME)

    def _client_ip_key(self) -> str:
        fallback = self.client_address[0] if getattr(self, "client_address", None) else ""
        return get_client_ip_key(self.headers, fallback_addr=fallback)

    def _is_geo_blocked(self) -> bool:
        return is_country_blocked(get_request_country(self.headers))

    def _is_authenticated(self) -> bool:
        return verify_session_token(self._get_session_cookie())

    def _effective_github_token(self) -> str:
        return get_server_github_token()

    def _is_valid_post_origin(self) -> bool:
        sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sec_site and sec_site not in ("same-origin", "none"):
            return False

        origin = (self.headers.get("Origin") or "").strip()
        host = (self.headers.get("Host") or "").strip().lower()
        if origin:
            try:
                parsed = urllib.parse.urlparse(origin)
                o_host = (parsed.netloc or "").lower()
                if origin == SITE_ORIGIN:
                    return True
                if host and o_host == host and parsed.scheme in ("https", "http"):
                    return True
                if parsed.hostname in ("localhost", "127.0.0.1"):
                    return True
            except Exception:
                return False
            return False

        # In Vercel production, require either valid Origin or Sec-Fetch-Site: same-origin
        if os.environ.get("VERCEL") == "1" and sec_site != "same-origin":
            return False
        return True

    def _send_json(
        self,
        status: int,
        data: dict | list,
        *,
        cache: str = "no-store",
        set_cookies: list[str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        if set_cookies:
            for ck in set_cookies:
                self.send_header("Set-Cookie", ck)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_not_found_html(self):
        html = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'/>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            "<meta name='robots' content='noindex,nofollow'/>"
            "<title>404 — Page Not Found | Saint Gordon Collective</title>"
            "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f2f2f2;color:#101010;"
            "font-family:'Courier New',monospace;padding:24px;}main{max-width:520px;background:#fff;border:1px solid #101010;"
            "padding:36px;box-shadow:7px 7px 0 #101010;}h1{font-family:Georgia,serif;margin:12px 0 10px;font-size:30px;}"
            "p{font-family:Arial,sans-serif;line-height:1.6;color:#303030;}a{color:#101010;font-weight:700;}</style></head>"
            "<body><main><div>HTTP 404 // NOT FOUND</div><h1>Page Not Found.</h1>"
            "<p>The page you are looking for does not exist or has been moved.</p>"
            "<p><a href='/'>← Return Home</a></p></main></body></html>"
        ).encode("utf-8")
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > MAX_JSON_BODY_BYTES:
            raise ValueError("Request body empty or exceeds 5 MB limit.")
        raw = self.rfile.read(length)
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object.")
        return parsed

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_url.query)
        action = (params.get("action", ["list"])[0] or "list").strip().lower()

        if action in ("not_found", "geo_blocked"):
            self._send_not_found_html()
            return

        if action in ADMIN_ACTIONS and self._is_geo_blocked():
            self._send_json(404, {"error": "Not found."})
            return

        is_admin = self._is_authenticated()
        token = self._effective_github_token() if is_admin else get_server_github_token()

        if action == "challenge":
            fails, _, retry_after = get_lockout_status(self._client_ip_key(), self._get_lockout_cookie())
            if retry_after > 0:
                self._send_json(
                    429,
                    {
                        "error": f"Too many failed attempts. Please wait {retry_after}s before trying again.",
                        "code": "RATE_LIMITED",
                        "retryAfter": retry_after,
                        "fails": fails,
                    },
                    extra_headers={"Retry-After": str(retry_after)},
                )
                return
            ch = create_login_challenge()
            self._send_json(200, ch)
            return

        if action == "session":
            _, _, retry_after = get_lockout_status(self._client_ip_key(), self._get_lockout_cookie())
            if not is_admin:
                self._send_json(200, {
                    "authenticated": False,
                    "retryAfter": retry_after,
                })
                return
            self._send_json(200, {
                "authenticated": True,
                "cloudConfigured": bool(get_server_github_token()),
                "retryAfter": 0,
            })
            return

        if action == "media":
            filename = (params.get("file", [""])[0] or "").strip()
            raw, mime = read_media_bytes(filename, token=token)
            if raw is None:
                self._send_json(404, {"error": "Media file not found."})
                return
            self.send_response(200)
            self.send_header("Content-Type", mime or mimetypes.guess_type(filename)[0] or "application/octet-stream")
            self.send_header("Cache-Control", "public, max-age=31536000, s-maxage=31536000, immutable")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Disposition", f'inline; filename="{Path(filename).name}"')
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if action == "admin_list":
            if not is_admin:
                self._send_json(401, {"error": "Authentication required."})
                return
            posts = read_all_admin_posts(token=token, prefer_live=True)
            media = github_list_media(token=token)
            self._send_json(200, {
                "posts": posts,
                "media": media,
                "cloudConfigured": bool(get_server_github_token()),
            })
            return

        if action == "list_media":
            if not is_admin:
                self._send_json(401, {"error": "Authentication required."})
                return
            self._send_json(200, {"media": github_list_media(token=token)})
            return

        if action == "post":
            slug = sanitize_slug(params.get("slug", [""])[0])
            if not slug:
                self._send_json(400, {"error": "Missing or invalid post slug."})
                return
            all_posts = read_all_admin_posts(token=token, prefer_live=True) if is_admin else read_posts_index(token=token, prefer_live=True)[0]
            entry = next((p for p in all_posts if p.get("slug") == slug), None)
            meta, body = read_post_markdown(slug, token=token, prefer_live=True, include_drafts=is_admin)
            if meta is None or body is None:
                self._send_json(404, {"error": "Post not found."})
                return
            merged = {**(entry or {}), **meta, "slug": slug}
            if merged.get("status", "published") != "published" and not is_admin:
                self._send_json(404, {"error": "Post not found."})
                return
            self._send_json(
                200,
                {"post": merged, "body": body},
                cache="private, no-store" if is_admin else "public, max-age=15, s-maxage=30, stale-while-revalidate=300",
            )
            return

        # Default public list: published posts sorted newest first
        posts, _ = read_posts_index(token=token, prefer_live=True)
        published = [p for p in posts if p.get("status", "published") == "published"]
        self._send_json(
            200,
            {"posts": published},
            cache="private, no-store" if is_admin else "public, max-age=15, s-maxage=30, stale-while-revalidate=300",
        )

    def do_POST(self):
        # All POST actions are admin actions — stealth 404 for geo-blocked regions
        if self._is_geo_blocked():
            self._send_json(404, {"error": "Not found."})
            return

        if not self._is_valid_post_origin():
            self._send_json(403, {"error": "Forbidden."})
            return

        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self._send_json(415, {"error": "Invalid request."})
            return

        try:
            body = self._read_json_body()
        except Exception as err:
            self._send_json(400, {"error": str(err)})
            return

        action = str(body.get("action") or "").strip().lower()
        secure_attr = "; Secure" if self._is_https() else ""

        if action == "login":
            ip_key = self._client_ip_key()
            lockout_ck = self._get_lockout_cookie()
            fails, _, retry_after = get_lockout_status(ip_key, lockout_ck)
            if retry_after > 0:
                self._send_json(
                    429,
                    {
                        "error": f"Too many failed attempts. Locked for {retry_after}s.",
                        "code": "RATE_LIMITED",
                        "retryAfter": retry_after,
                        "fails": fails,
                    },
                    extra_headers={"Retry-After": str(retry_after)},
                )
                return

            # Reject plaintext password transmission
            if "password" in body:
                self._send_json(400, {"error": "Invalid request."})
                return

            ok, err_msg = verify_login_envelope(
                str(body.get("nonce") or ""),
                body.get("exp"),
                str(body.get("sig") or ""),
                str(body.get("epk") or ""),
                str(body.get("ct") or ""),
                str(body.get("tag") or ""),
            )
            if not ok:
                new_fails, _, timeout_sec, bf_val = record_failed_login(ip_key, lockout_ck)
                time.sleep(0.5)
                bf_cookie = (
                    f"{LOCKOUT_COOKIE_NAME}={bf_val}; HttpOnly; Path=/; "
                    f"SameSite=Strict; Max-Age={LOCKOUT_STATE_EXPIRY_SECONDS}{secure_attr}"
                )
                self._send_json(
                    429 if new_fails >= 1 else 401,
                    {
                        "error": f"{err_msg} Wait {timeout_sec}s before trying again.",
                        "code": "RATE_LIMITED",
                        "retryAfter": timeout_sec,
                        "fails": new_fails,
                    },
                    set_cookies=[bf_cookie],
                    extra_headers={"Retry-After": str(timeout_sec)},
                )
                return

            clear_failed_logins(ip_key)
            token_val = create_session_token()
            session_cookie = (
                f"{SESSION_COOKIE_NAME}={token_val}; HttpOnly; Path=/; "
                f"SameSite=Strict; Max-Age={SESSION_TTL_SECONDS}{secure_attr}"
            )
            clear_bf_cookie = (
                f"{LOCKOUT_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0{secure_attr}"
            )
            self._send_json(
                200,
                {
                    "ok": True,
                    "authenticated": True,
                    "cloudConfigured": bool(get_server_github_token()),
                },
                set_cookies=[session_cookie, clear_bf_cookie],
            )
            return

        if action == "logout":
            cookie_hdr = f"{SESSION_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0{secure_attr}"
            self._send_json(200, {"ok": True, "authenticated": False}, set_cookies=[cookie_hdr])
            return

        # Every write action below strictly requires a valid verified session cookie
        if not self._is_authenticated():
            self._send_json(401, {"error": "Admin session expired or missing. Please log in again."})
            return

        gh_token = self._effective_github_token()
        if not gh_token:
            self._send_json(
                503,
                {
                    "error": "Cloud publishing storage is not configured.",
                    "code": "STORAGE_OFFLINE",
                },
            )
            return

        try:
            if action == "save_post":
                result = self._handle_save_post(body, gh_token)
                self._send_json(200, result)
                return
            if action == "delete_post":
                result = self._handle_delete_post(body, gh_token)
                self._send_json(200, result)
                return
            if action in ("toggle_status", "toggle_pin"):
                result = self._handle_quick_toggle(action, body, gh_token)
                self._send_json(200, result)
                return
            if action == "upload_media":
                result = self._handle_upload_media(body, gh_token)
                self._send_json(200, result)
                return
            if action == "delete_media":
                result = self._handle_delete_media(body, gh_token)
                self._send_json(200, result)
                return
            self._send_json(400, {"error": "Invalid action."})
        except ValueError as err:
            self._send_json(400, {"error": str(err)})
        except Exception as err:
            self.log_error("Writings API write error: %s", err)
            self._send_json(502, {"error": "Unable to complete publishing request right now."})

    def _handle_save_post(self, body: dict, gh_token: str) -> dict:
        title = str(body.get("title") or "").strip()
        if not title:
            raise ValueError("Post title is required.")
        raw_slug = str(body.get("slug") or title)
        slug = sanitize_slug(raw_slug)
        if not slug or not SLUG_RE.match(slug):
            raise ValueError("Post slug must contain letters or numbers.")

        original_slug = sanitize_slug(str(body.get("originalSlug") or ""))
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        date_str = str(body.get("date") or now_iso[:10]).strip()[:10]
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
            date_str = now_iso[:10]

        status = "draft" if str(body.get("status") or "").lower() == "draft" else "published"
        pinned = bool(body.get("pinned", False))
        summary = str(body.get("summary") or "").strip()[:320]
        cover_image = str(body.get("coverImage") or "").strip()[:500]
        raw_tags = body.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [t.strip() for t in raw_tags.split(",")]
        tags = []
        seen_tags = set()
        for t in raw_tags:
            cleaned = str(t).strip()[:32]
            if cleaned and cleaned.lower() not in seen_tags:
                seen_tags.add(cleaned.lower())
                tags.append(cleaned)

        md_body = str(body.get("body") or "")
        plain_text = strip_markdown(md_body)
        if not summary:
            summary = (plain_text[:175] + "…") if len(plain_text) > 175 else plain_text

        post_meta = {
            "slug": slug,
            "title": title,
            "date": date_str,
            "updatedAt": now_iso,
            "status": status,
            "pinned": pinned,
            "tags": tags,
            "summary": summary,
            "coverImage": cover_image,
            "readingTimeMin": estimate_reading_time(md_body),
            "wordCount": len(plain_text.split()) if plain_text else 0,
            "searchText": plain_text[:2400],
        }

        md_content = serialize_post_markdown(post_meta, md_body).encode("utf-8")
        pub_posts, pub_sha = read_posts_index(token=gh_token, prefer_live=True)
        draft_posts, draft_sha = read_drafts_index(token=gh_token, prefer_live=True)

        def _without_slugs(items: list[dict]) -> list[dict]:
            return [
                p for p in items
                if p.get("slug") != slug and (not original_slug or p.get("slug") != original_slug)
            ]

        next_pubs = _without_slugs(pub_posts)
        next_drafts = _without_slugs(draft_posts)

        if status == "published":
            github_put_file(
                f"{POSTS_DIR_REL}/{slug}.md",
                md_content,
                f"writings: save post '{title}' ({slug})",
                token=gh_token,
            )
            next_pubs = sort_posts_newest(next_pubs + [post_meta])
            github_put_file(
                POSTS_INDEX_REL,
                (json.dumps(next_pubs, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                f"writings: update index for '{slug}'",
                token=gh_token,
                sha=pub_sha,
            )
            # Remove from drafts index & _drafts folder if previously saved as a draft
            if len(next_drafts) != len(draft_posts):
                github_put_file(
                    DRAFTS_INDEX_REL,
                    (json.dumps(sort_posts_newest(next_drafts), indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                    f"writings: promote draft '{slug}'",
                    token=gh_token,
                    sha=draft_sha,
                )
            for cleanup_slug in ({slug, original_slug} - {""}):
                try:
                    github_delete_file(f"{DRAFTS_DIR_REL}/{cleanup_slug}.md", f"writings: clean draft '{cleanup_slug}'", token=gh_token)
                except Exception:
                    pass
            if original_slug and original_slug != slug:
                try:
                    github_delete_file(
                        f"{POSTS_DIR_REL}/{original_slug}.md",
                        f"writings: remove renamed post '{original_slug}'",
                        token=gh_token,
                    )
                except Exception:
                    pass
            try:
                github_put_file(
                    FEED_REL,
                    build_rss_feed(next_pubs).encode("utf-8"),
                    "writings: refresh RSS feed",
                    token=gh_token,
                )
            except Exception:
                pass
        else:
            # Store strictly in isolated _drafts index & folder — zero draft entries in public posts.json!
            github_put_file(
                f"{DRAFTS_DIR_REL}/{slug}.md",
                md_content,
                f"writings: save draft ({slug})",
                token=gh_token,
            )
            next_drafts = sort_posts_newest(next_drafts + [post_meta])
            github_put_file(
                DRAFTS_INDEX_REL,
                (json.dumps(next_drafts, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                f"writings: update drafts index for '{slug}'",
                token=gh_token,
                sha=draft_sha,
            )
            if len(next_pubs) != len(pub_posts):
                next_pubs = sort_posts_newest(next_pubs)
                github_put_file(
                    POSTS_INDEX_REL,
                    (json.dumps(next_pubs, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                    f"writings: unpublish '{slug}' to draft",
                    token=gh_token,
                    sha=pub_sha,
                )
                try:
                    github_put_file(FEED_REL, build_rss_feed(next_pubs).encode("utf-8"), "writings: refresh RSS feed", token=gh_token)
                except Exception:
                    pass
            for cleanup_slug in ({slug, original_slug} - {""}):
                try:
                    github_delete_file(f"{POSTS_DIR_REL}/{cleanup_slug}.md", f"writings: unpublish '{cleanup_slug}'", token=gh_token)
                except Exception:
                    pass
            if original_slug and original_slug != slug:
                try:
                    github_delete_file(f"{DRAFTS_DIR_REL}/{original_slug}.md", f"writings: rename draft '{original_slug}'", token=gh_token)
                except Exception:
                    pass

        combined = sort_posts_newest(next_pubs + next_drafts)
        return {"ok": True, "post": post_meta, "posts": combined}

    def _handle_delete_post(self, body: dict, gh_token: str) -> dict:
        slug = sanitize_slug(str(body.get("slug") or ""))
        if not slug:
            raise ValueError("Invalid post slug.")

        pub_posts, pub_sha = read_posts_index(token=gh_token, prefer_live=True)
        draft_posts, draft_sha = read_drafts_index(token=gh_token, prefer_live=True)

        rem_pubs = sort_posts_newest([p for p in pub_posts if p.get("slug") != slug])
        rem_drafts = sort_posts_newest([p for p in draft_posts if p.get("slug") != slug])

        try:
            github_delete_file(f"{POSTS_DIR_REL}/{slug}.md", f"writings: delete post '{slug}'", token=gh_token)
        except Exception:
            pass
        try:
            github_delete_file(f"{DRAFTS_DIR_REL}/{slug}.md", f"writings: delete draft '{slug}'", token=gh_token)
        except Exception:
            pass

        if len(rem_pubs) != len(pub_posts):
            github_put_file(
                POSTS_INDEX_REL,
                (json.dumps(rem_pubs, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                f"writings: remove '{slug}' from index",
                token=gh_token,
                sha=pub_sha,
            )
            try:
                github_put_file(FEED_REL, build_rss_feed(rem_pubs).encode("utf-8"), "writings: refresh RSS feed", token=gh_token)
            except Exception:
                pass

        if len(rem_drafts) != len(draft_posts):
            github_put_file(
                DRAFTS_INDEX_REL,
                (json.dumps(rem_drafts, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                f"writings: remove draft '{slug}'",
                token=gh_token,
                sha=draft_sha,
            )

        return {"ok": True, "posts": sort_posts_newest(rem_pubs + rem_drafts)}

    def _handle_quick_toggle(self, action: str, body: dict, gh_token: str) -> dict:
        slug = sanitize_slug(str(body.get("slug") or ""))
        if not slug:
            raise ValueError("Invalid post slug.")
        pub_posts, pub_sha = read_posts_index(token=gh_token, prefer_live=True)
        draft_posts, draft_sha = read_drafts_index(token=gh_token, prefer_live=True)
        all_posts = {p.get("slug"): p for p in (pub_posts + draft_posts) if p.get("slug")}
        target = all_posts.get(slug)
        if not target:
            raise ValueError("Post not found.")
        _, md_body = read_post_markdown(slug, token=gh_token, prefer_live=True, include_drafts=True)
        if md_body is None:
            md_body = ""
        updated = dict(target)
        updated["updatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if action == "toggle_status":
            updated["status"] = "draft" if updated.get("status", "published") == "published" else "published"
        elif action == "toggle_pin":
            updated["pinned"] = not bool(updated.get("pinned", False))

        new_status = updated.get("status", "published")
        md_bytes = serialize_post_markdown(updated, md_body).encode("utf-8")

        next_pubs = [p for p in pub_posts if p.get("slug") != slug]
        next_drafts = [p for p in draft_posts if p.get("slug") != slug]

        if new_status == "published":
            next_pubs = sort_posts_newest(next_pubs + [updated])
            next_drafts = sort_posts_newest(next_drafts)
            github_put_file(f"{POSTS_DIR_REL}/{slug}.md", md_bytes, f"writings: {action} '{slug}'", token=gh_token)
            github_put_file(
                POSTS_INDEX_REL,
                (json.dumps(next_pubs, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                f"writings: update index ({action} '{slug}')",
                token=gh_token,
                sha=pub_sha,
            )
            if len(next_drafts) != len(draft_posts):
                github_put_file(
                    DRAFTS_INDEX_REL,
                    (json.dumps(next_drafts, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                    f"writings: remove published draft '{slug}'",
                    token=gh_token,
                    sha=draft_sha,
                )
                try:
                    github_delete_file(f"{DRAFTS_DIR_REL}/{slug}.md", f"writings: clean draft '{slug}'", token=gh_token)
                except Exception:
                    pass
            try:
                github_put_file(FEED_REL, build_rss_feed(next_pubs).encode("utf-8"), "writings: refresh RSS feed", token=gh_token)
            except Exception:
                pass
        else:
            next_pubs = sort_posts_newest(next_pubs)
            next_drafts = sort_posts_newest(next_drafts + [updated])
            github_put_file(f"{DRAFTS_DIR_REL}/{slug}.md", md_bytes, f"writings: {action} '{slug}'", token=gh_token)
            github_put_file(
                DRAFTS_INDEX_REL,
                (json.dumps(next_drafts, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                f"writings: update drafts ({action} '{slug}')",
                token=gh_token,
                sha=draft_sha,
            )
            if len(next_pubs) != len(pub_posts):
                github_put_file(
                    POSTS_INDEX_REL,
                    (json.dumps(next_pubs, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                    f"writings: remove unpublished '{slug}' from index",
                    token=gh_token,
                    sha=pub_sha,
                )
                try:
                    github_delete_file(f"{POSTS_DIR_REL}/{slug}.md", f"writings: move '{slug}' to drafts", token=gh_token)
                except Exception:
                    pass
                try:
                    github_put_file(FEED_REL, build_rss_feed(next_pubs).encode("utf-8"), "writings: refresh RSS feed", token=gh_token)
                except Exception:
                    pass

        return {"ok": True, "post": updated, "posts": sort_posts_newest(next_pubs + next_drafts)}

    def _handle_upload_media(self, body: dict, gh_token: str) -> dict:
        raw_name = str(body.get("filename") or "image.jpg")
        b64_data = str(body.get("dataBase64") or "")
        if "," in b64_data and b64_data.startswith("data:"):
            b64_data = b64_data.split(",", 1)[1]
        if not b64_data:
            raise ValueError("Missing base64 file data.")
        try:
            raw_bytes = base64.b64decode(b64_data, validate=True)
        except Exception:
            raise ValueError("Invalid base64 media payload.")
        if len(raw_bytes) > MAX_MEDIA_RAW_BYTES:
            raise ValueError("File exceeds 3 MB upload limit. Compress image or embed larger videos via YouTube/Vimeo.")

        safe_name = sanitize_filename(raw_name)
        ext = Path(safe_name).suffix.lower()
        validate_media_magic_bytes(raw_bytes, ext)
        rel_path = f"{MEDIA_DIR_REL}/{safe_name}"
        github_put_file(
            rel_path,
            raw_bytes,
            f"writings: upload media '{safe_name}'",
            token=gh_token,
        )
        mime = ALLOWED_MEDIA_EXTS[ext]
        kind = "video" if mime.startswith("video/") else "audio" if mime.startswith("audio/") else "image"
        caption = Path(raw_name).stem.replace("-", " ").replace("_", " ").strip() or "Media"
        live_url = f"/api/writings?action=media&file={urllib.parse.quote(safe_name)}"
        md_snippet = f"![{caption}]({rel_path})"

        return {
            "ok": True,
            "media": {
                "filename": safe_name,
                "path": rel_path,
                "liveUrl": live_url,
                "size": len(raw_bytes),
                "mime": mime,
                "kind": kind,
                "markdown": md_snippet,
            },
        }

    def _handle_delete_media(self, body: dict, gh_token: str) -> dict:
        filename = str(body.get("filename") or "").strip()
        if not SAFE_FILENAME_RE.match(filename) or ".." in filename or "/" in filename:
            raise ValueError("Invalid media filename.")
        github_delete_file(
            f"{MEDIA_DIR_REL}/{filename}",
            f"writings: delete media '{filename}'",
            token=gh_token,
        )
        return {"ok": True, "media": github_list_media(token=gh_token)}
