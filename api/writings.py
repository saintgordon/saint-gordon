"""
Saint Gordon Collective — Writings CMS Serverless API (Vercel Python)

Endpoints:
  GET  /api/writings?action=list                 Public published posts (newest first)
  GET  /api/writings?action=post&slug=<slug>     Single post metadata + Markdown body
  GET  /api/writings?action=media&file=<name>    Live media proxy for newly uploaded files
  GET  /api/writings?action=session              Check admin session + cloud storage status
  GET  /api/writings?action=admin_list           All posts (published + drafts) & media [auth]
  GET  /api/writings?action=list_media           Media library files [auth]

  POST /api/writings  { action: "login", password }            Password-only SHA3-512 login
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
MEDIA_DIR_REL = "writings/media"
FEED_REL = "writings/feed.xml"

DEFAULT_PASSWORD_SHA3_512 = (
    "c1e3393cd6e7032469e2754338a5b209b0910ed4afa43fbdced4961849f13f06"
    "fa9dea814dd79f5081824111f90608176bc3ff27d3774088f854195ec4c6c926"
)
DEFAULT_GITHUB_REPO = "saintgordon/saint-gordon"
DEFAULT_GITHUB_BRANCH = "main"
SITE_ORIGIN = "https://saintgordon.vercel.app"

SESSION_COOKIE_NAME = "sg_writings_session"
LOCKOUT_COOKIE_NAME = "sg_writings_bf"
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
CHALLENGE_TTL_SECONDS = 60  # One-time login challenge expires in 60 seconds
MAX_JSON_BODY_BYTES = 5 * 1024 * 1024
MAX_MEDIA_RAW_BYTES = 4_200_000  # Safely under Vercel's 4.5 MB serverless limit

# Admin Geo-Blocker: China (CN), Israel (IL), Russia (RU), Iran (IR), India (IN)
BLOCKED_ADMIN_COUNTRIES = frozenset({"CN", "IL", "RU", "IR", "IN"})
BLOCKED_COUNTRY_NAMES = {
    "CN": "China",
    "IL": "Israel",
    "RU": "Russia",
    "IR": "Iran",
    "IN": "India",
}

# Exponential anti-bruteforce lockout schedule (seconds per consecutive failed attempt)
LOCKOUT_SCHEDULE_SECONDS = (5, 15, 30, 120, 300, 900)
LOCKOUT_STATE_EXPIRY_SECONDS = 1800

# Actions restricted to admin (subject to geo-blocker)
ADMIN_ACTIONS = frozenset({
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
# Auth & Crypto Helpers (Zero-Username, SHA3-512 Password Verification)
# ---------------------------------------------------------------------------

def get_expected_password_hash() -> str:
    return (os.environ.get("WRITINGS_PASSWORD_HASH") or DEFAULT_PASSWORD_SHA3_512).strip().lower()


def compute_sha3_512(password: str) -> str:
    return hashlib.sha3_512(password.encode("utf-8")).hexdigest()


def verify_password(password: str) -> bool:
    if not isinstance(password, str) or not password:
        return False
    computed = compute_sha3_512(password)
    return hmac.compare_digest(computed, get_expected_password_hash())


def _session_secret() -> bytes:
    seed = (
        os.environ.get("WRITINGS_SESSION_SECRET")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("WRITINGS_GITHUB_TOKEN")
        or f"{get_expected_password_hash()}::saint-gordon-writings-session-v1"
    )
    return hashlib.sha256(seed.encode("utf-8")).digest()


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
        xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for") or ""
        if xff:
            raw_ip = xff.split(",")[0].strip()
        if not raw_ip:
            raw_ip = (headers.get("X-Real-IP") or headers.get("x-real-ip") or "").strip()
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


def create_login_challenge(now: int | None = None) -> dict:
    ts = int(time.time()) if now is None else int(now)
    nonce = secrets.token_hex(32)
    exp = ts + CHALLENGE_TTL_SECONDS
    msg = f"challenge:{nonce}:{exp}".encode("ascii")
    sig = hmac.new(_session_secret(), msg, hashlib.sha256).hexdigest()
    return {"nonce": nonce, "exp": exp, "sig": sig}


def compute_expected_login_proof(nonce: str, exp: int, expected_sha3_512: str | None = None) -> str:
    key_hex = (expected_sha3_512 or get_expected_password_hash()).strip().lower()
    msg = f"{nonce}:{exp}".encode("ascii")
    return hmac.new(key_hex.encode("ascii"), msg, hashlib.sha256).hexdigest()


def verify_login_challenge_proof(
    nonce: str,
    exp: int,
    sig: str,
    proof: str,
    *,
    now: int | None = None,
    consume_nonce: bool = True,
) -> tuple[bool, str]:
    ts = int(time.time()) if now is None else int(now)
    _prune_caches(ts)

    if not nonce or not isinstance(nonce, str) or len(nonce) != 64:
        return False, "Invalid login challenge."
    try:
        exp_int = int(exp)
    except Exception:
        return False, "Invalid challenge expiry."
    if ts > exp_int or exp_int > ts + CHALLENGE_TTL_SECONDS + 10:
        return False, "Login challenge expired. Please try again."

    expected_sig = hmac.new(
        _session_secret(),
        f"challenge:{nonce}:{exp_int}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(sig, str) or not hmac.compare_digest(sig.lower(), expected_sig):
        return False, "Invalid challenge signature."

    if nonce in _USED_NONCES:
        return False, "Login challenge already used. Please try again."
    if consume_nonce:
        _USED_NONCES[nonce] = exp_int + 10

    if not isinstance(proof, str) or len(proof) != 64:
        return False, "Incorrect password."
    expected_proof = compute_expected_login_proof(nonce, exp_int)
    if not hmac.compare_digest(proof.lower(), expected_proof):
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
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("WRITINGS_GITHUB_TOKEN") or "").strip()


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
        if data.get("download_url"):
            req = urllib.request.Request(
                data["download_url"],
                headers={"User-Agent": "SaintGordon-Writings-CMS/1.0", **({"Authorization": f"Bearer {token}"} if token else {})},
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                return resp.read(), sha
    return None, None


def github_put_file(rel_path: str, content_bytes: bytes, message: str, token: str, sha: str | None = None) -> dict:
    repo, branch = get_repo_config()
    if sha is None:
        _, existing_sha = github_get_file(rel_path, token=token)
        sha = existing_sha
    payload: dict = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode("ascii"),
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha
    quoted = urllib.parse.quote(rel_path, safe="/")
    status, data = _github_request("PUT", f"/repos/{repo}/contents/{quoted}", token=token, payload=payload)
    if status not in (200, 201):
        msg = data.get("message") if isinstance(data, dict) else f"GitHub HTTP {status}"
        raise RuntimeError(f"GitHub write failed ({status}): {msg}")
    return data if isinstance(data, dict) else {}


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
    if prefer_live:
        try:
            raw, sha = github_get_file(POSTS_INDEX_REL, token=token)
            if raw is not None:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, list):
                    return sort_posts_newest(parsed), sha
        except Exception:
            pass

    local_path = ROOT_DIR / POSTS_INDEX_REL
    if local_path.is_file():
        try:
            parsed = json.loads(local_path.read_text(encoding="utf-8"))
            if isinstance(parsed, list):
                return sort_posts_newest(parsed), None
        except Exception:
            pass
    return [], None


def read_post_markdown(slug: str, token: str = "", prefer_live: bool = True) -> tuple[dict, str] | tuple[None, None]:
    if not SLUG_RE.match(slug):
        return None, None
    rel_path = f"{POSTS_DIR_REL}/{slug}.md"
    if prefer_live:
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
        env_token = get_server_github_token()
        if env_token:
            return env_token
        header_token = (self.headers.get("X-GitHub-Token") or "").strip()
        return header_token

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

    def _send_geo_blocked_html(self):
        html = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'/>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            "<meta name='robots' content='noindex,nofollow'/>"
            "<title>403 — Access Restricted | Saint Gordon Collective</title>"
            "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f2f2f2;color:#101010;"
            "font-family:'Courier New',monospace;padding:24px;}main{max-width:520px;background:#fff;border:1px solid #101010;"
            "padding:36px;box-shadow:7px 7px 0 #101010;}h1{font-family:Georgia,serif;margin:12px 0 10px;font-size:28px;}"
            "p{font-family:Arial,sans-serif;line-height:1.6;color:#303030;}a{color:#101010;}</style></head>"
            "<body><main><div>HTTP 403 // REGION RESTRICTED</div><h1>Admin Access Unavailable</h1>"
            "<p>The Saint Gordon Writings admin portal is not accessible from your region.</p>"
            "<p><a href='/writings'>← Return to Public Writings</a></p></main></body></html>"
        ).encode("utf-8")
        self.send_response(403)
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

        if action == "geo_blocked":
            self._send_geo_blocked_html()
            return

        if action in ADMIN_ACTIONS and self._is_geo_blocked():
            self._send_json(403, {"error": "Admin access is restricted in your region.", "code": "GEO_BLOCKED"})
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
            repo, branch = get_repo_config()
            fails, _, retry_after = get_lockout_status(self._client_ip_key(), self._get_lockout_cookie())
            self._send_json(200, {
                "authenticated": is_admin,
                "cloudConfigured": bool(get_server_github_token()),
                "repo": repo,
                "branch": branch,
                "retryAfter": retry_after,
                "fails": fails,
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
            self.send_header("Cache-Control", "public, max-age=3600, s-maxage=3600")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if action == "admin_list":
            if not is_admin:
                self._send_json(401, {"error": "Authentication required."})
                return
            posts, _ = read_posts_index(token=token, prefer_live=True)
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
            posts, _ = read_posts_index(token=token, prefer_live=True)
            entry = next((p for p in posts if p.get("slug") == slug), None)
            meta, body = read_post_markdown(slug, token=token, prefer_live=True)
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
                cache="no-store" if is_admin else "public, max-age=30, s-maxage=30, stale-while-revalidate=120",
            )
            return

        # Default public list: published posts sorted newest first
        posts, _ = read_posts_index(token=token, prefer_live=True)
        published = [p for p in posts if p.get("status", "published") == "published"]
        self._send_json(
            200,
            {"posts": published},
            cache="public, max-age=30, s-maxage=30, stale-while-revalidate=120",
        )

    def do_POST(self):
        # All POST actions are admin actions — enforce geo-blocker first before reading body
        if self._is_geo_blocked():
            self._send_json(403, {"error": "Admin access is restricted in your region.", "code": "GEO_BLOCKED"})
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

            # Reject plaintext password transmission — enforce zero-plaintext challenge-response
            if "password" in body:
                self._send_json(
                    400,
                    {"error": "Plaintext password submission is disabled. Refresh the page and sign in securely."},
                )
                return

            ok, err_msg = verify_login_challenge_proof(
                str(body.get("nonce") or ""),
                body.get("exp"),
                str(body.get("sig") or ""),
                str(body.get("proof") or ""),
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
            repo, branch = get_repo_config()
            self._send_json(
                200,
                {
                    "ok": True,
                    "authenticated": True,
                    "cloudConfigured": bool(get_server_github_token()),
                    "repo": repo,
                    "branch": branch,
                },
                set_cookies=[session_cookie, clear_bf_cookie],
            )
            return

        if action == "logout":
            cookie_hdr = f"{SESSION_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0{secure_attr}"
            self._send_json(200, {"ok": True, "authenticated": False}, set_cookies=[cookie_hdr])
            return

        # Every write action below strictly requires a valid SHA3-512 verified session cookie
        if not self._is_authenticated():
            self._send_json(401, {"error": "Admin session expired or missing. Please log in again."})
            return

        gh_token = self._effective_github_token()
        if not gh_token:
            self._send_json(
                503,
                {
                    "error": "GitHub write token not configured yet. Add GITHUB_TOKEN in Vercel Environment Variables (or connect a scoped token in Admin Settings).",
                    "code": "NO_GITHUB_TOKEN",
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
            self._send_json(400, {"error": f"Unknown action '{action}'."})
        except ValueError as err:
            self._send_json(400, {"error": str(err)})
        except Exception as err:
            self._send_json(502, {"error": str(err)})

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

        # 1. Write Markdown file
        md_content = serialize_post_markdown(post_meta, md_body)
        github_put_file(
            f"{POSTS_DIR_REL}/{slug}.md",
            md_content.encode("utf-8"),
            f"writings: save post '{title}' ({slug})",
            token=gh_token,
        )

        # 2. Update posts.json index
        posts, idx_sha = read_posts_index(token=gh_token, prefer_live=True)
        filtered = [
            p for p in posts
            if p.get("slug") != slug and (not original_slug or p.get("slug") != original_slug)
        ]
        filtered.append(post_meta)
        sorted_posts = sort_posts_newest(filtered)

        github_put_file(
            POSTS_INDEX_REL,
            (json.dumps(sorted_posts, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
            f"writings: update index for '{slug}'",
            token=gh_token,
            sha=idx_sha,
        )

        # 3. Clean up renamed old slug file if slug changed
        if original_slug and original_slug != slug:
            try:
                github_delete_file(
                    f"{POSTS_DIR_REL}/{original_slug}.md",
                    f"writings: remove renamed post '{original_slug}'",
                    token=gh_token,
                )
            except Exception:
                pass

        # 4. Update RSS feed
        try:
            github_put_file(
                FEED_REL,
                build_rss_feed(sorted_posts).encode("utf-8"),
                f"writings: refresh RSS feed",
                token=gh_token,
            )
        except Exception:
            pass

        return {"ok": True, "post": post_meta, "posts": sorted_posts}

    def _handle_delete_post(self, body: dict, gh_token: str) -> dict:
        slug = sanitize_slug(str(body.get("slug") or ""))
        if not slug:
            raise ValueError("Invalid post slug.")

        github_delete_file(
            f"{POSTS_DIR_REL}/{slug}.md",
            f"writings: delete post '{slug}'",
            token=gh_token,
        )
        posts, idx_sha = read_posts_index(token=gh_token, prefer_live=True)
        remaining = sort_posts_newest([p for p in posts if p.get("slug") != slug])
        github_put_file(
            POSTS_INDEX_REL,
            (json.dumps(remaining, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
            f"writings: remove '{slug}' from index",
            token=gh_token,
            sha=idx_sha,
        )
        try:
            github_put_file(FEED_REL, build_rss_feed(remaining).encode("utf-8"), "writings: refresh RSS feed", token=gh_token)
        except Exception:
            pass
        return {"ok": True, "posts": remaining}

    def _handle_quick_toggle(self, action: str, body: dict, gh_token: str) -> dict:
        slug = sanitize_slug(str(body.get("slug") or ""))
        if not slug:
            raise ValueError("Invalid post slug.")
        posts, idx_sha = read_posts_index(token=gh_token, prefer_live=True)
        target = next((p for p in posts if p.get("slug") == slug), None)
        if not target:
            raise ValueError("Post not found.")
        meta, md_body = read_post_markdown(slug, token=gh_token, prefer_live=True)
        if md_body is None:
            md_body = ""
        updated = dict(target)
        updated["updatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if action == "toggle_status":
            updated["status"] = "draft" if updated.get("status", "published") == "published" else "published"
        elif action == "toggle_pin":
            updated["pinned"] = not bool(updated.get("pinned", False))

        github_put_file(
            f"{POSTS_DIR_REL}/{slug}.md",
            serialize_post_markdown(updated, md_body).encode("utf-8"),
            f"writings: {action} '{slug}'",
            token=gh_token,
        )
        next_posts = sort_posts_newest([updated if p.get("slug") == slug else p for p in posts])
        github_put_file(
            POSTS_INDEX_REL,
            (json.dumps(next_posts, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
            f"writings: update index ({action} '{slug}')",
            token=gh_token,
            sha=idx_sha,
        )
        try:
            github_put_file(FEED_REL, build_rss_feed(next_posts).encode("utf-8"), "writings: refresh RSS feed", token=gh_token)
        except Exception:
            pass
        return {"ok": True, "post": updated, "posts": next_posts}

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
            raise ValueError("File exceeds 4.2 MB upload limit. Compress image or embed larger videos via YouTube/Vimeo.")

        safe_name = sanitize_filename(raw_name)
        rel_path = f"{MEDIA_DIR_REL}/{safe_name}"
        github_put_file(
            rel_path,
            raw_bytes,
            f"writings: upload media '{safe_name}'",
            token=gh_token,
        )
        ext = Path(safe_name).suffix.lower()
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
