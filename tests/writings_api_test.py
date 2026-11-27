import base64
import hashlib
from http.server import HTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api import releases, writings


class _FakeGitHubStore:
    """In-memory mock of GitHub Contents API for full end-to-end HTTP CRUD testing."""

    def __init__(self):
        self.files: dict[str, bytes] = {
            writings.POSTS_INDEX_REL: b"[]\n",
        }

    def _sha(self, content: bytes) -> str:
        return hashlib.sha1(content).hexdigest()

    def request(self, method: str, api_path: str, token: str = "", payload: dict | None = None):
        prefix = "/repos/saintgordon/saint-gordon/contents/"
        assert api_path.startswith(prefix), f"Unexpected path: {api_path}"
        rel = api_path[len(prefix):].split("?", 1)[0]
        rel = urllib.request.unquote(rel)

        if method == "GET":
            if rel in self.files:
                raw = self.files[rel]
                return 200, {
                    "type": "file",
                    "name": Path(rel).name,
                    "sha": self._sha(raw),
                    "encoding": "base64",
                    "content": base64.b64encode(raw).decode("ascii"),
                    "size": len(raw),
                }
            # Directory listing
            dir_prefix = rel.rstrip("/") + "/"
            entries = []
            for k, raw in sorted(self.files.items()):
                if k.startswith(dir_prefix) and "/" not in k[len(dir_prefix):]:
                    entries.append({
                        "type": "file",
                        "name": Path(k).name,
                        "sha": self._sha(raw),
                        "size": len(raw),
                    })
            if entries:
                return 200, entries
            return 404, {"message": "Not Found"}

        if method == "PUT":
            assert payload is not None
            raw = base64.b64decode(payload["content"])
            self.files[rel] = raw
            return 200, {"content": {"sha": self._sha(raw)}}

        if method == "DELETE":
            if rel in self.files:
                del self.files[rel]
                return 200, {"commit": {"sha": "deleted"}}
            return 404, {"message": "Not Found"}

        return 405, {"message": "Method Not Allowed"}


class WritingsApiTests(unittest.TestCase):
    def test_exact_sha3_512_hash_configured(self):
        expected = (
            "c1e3393cd6e7032469e2754338a5b209b0910ed4afa43fbdced4961849f13f06"
            "fa9dea814dd79f5081824111f90608176bc3ff27d3774088f854195ec4c6c926"
        )
        self.assertEqual(writings.get_expected_password_hash(), expected)
        self.assertEqual(len(expected), 128)
        self.assertFalse(writings.verify_password(""))
        self.assertFalse(writings.verify_password("wrong-password-123"))

        # Heavy obfuscation checks (1A): no literal hash, env names, or AV-unsafe eval/exec in api/writings.py
        src = (ROOT / "api" / "writings.py").read_text(encoding="utf-8")
        self.assertNotIn(expected, src)
        self.assertNotIn(expected[:24], src)
        self.assertNotIn("WRITINGS_PASSWORD_HASH", src)
        self.assertNotIn("WRITINGS_SESSION_SECRET", src)
        self.assertNotIn("GITHUB_TOKEN", src)
        self.assertNotIn("sha3_512", src)
        self.assertNotIn("eval(", src)
        self.assertNotIn("exec(", src)

    def test_ip_spoofing_resistance_and_releases_cors(self):
        # 2C: Spoofed left-most X-Forwarded-For must NOT override x-real-ip or right-most XFF
        k_real = writings.get_client_ip_key({
            "X-Forwarded-For": "1.2.3.4, 203.0.113.9",
            "x-real-ip": "203.0.113.9",
        })
        k_spoof_attempt = writings.get_client_ip_key({
            "X-Forwarded-For": "99.88.77.66, 203.0.113.9",
            "x-real-ip": "203.0.113.9",
        })
        self.assertEqual(k_real, k_spoof_attempt)

        k_xff_rightmost = writings.get_client_ip_key({"X-Forwarded-For": "8.8.8.8, 198.51.100.42"})
        k_xff_spoof = writings.get_client_ip_key({"X-Forwarded-For": "4.4.4.4, 198.51.100.42"})
        self.assertEqual(k_xff_rightmost, k_xff_spoof)

        # Section 3.3: Restricted CORS on /api/releases (no wildcard *)
        self.assertIn("https://saintgordon.vercel.app", releases.ALLOWED_ORIGINS)
        self.assertIn("http://localhost:8000", releases.ALLOWED_ORIGINS)
        self.assertNotIn("*", releases.ALLOWED_ORIGINS)
        self.assertNotIn("https://evil.example", releases.ALLOWED_ORIGINS)

        rel_srv = HTTPServer(("127.0.0.1", 0), releases.handler)
        rel_thread = threading.Thread(target=rel_srv.serve_forever, daemon=True)
        rel_thread.start()
        try:
            with mock.patch.object(releases, "build", return_value=([{"slug": "t1"}], [])):
                req_ok = urllib.request.Request(
                    f"http://127.0.0.1:{rel_srv.server_port}/api/releases",
                    headers={"Origin": "https://saintgordon.vercel.app"},
                )
                with urllib.request.urlopen(req_ok, timeout=5) as r_ok:
                    self.assertEqual(r_ok.headers.get("Access-Control-Allow-Origin"), "https://saintgordon.vercel.app")
                req_evil = urllib.request.Request(
                    f"http://127.0.0.1:{rel_srv.server_port}/api/releases",
                    headers={"Origin": "https://evil.example"},
                )
                with urllib.request.urlopen(req_evil, timeout=5) as r_evil:
                    self.assertIsNone(r_evil.headers.get("Access-Control-Allow-Origin"))
        finally:
            rel_srv.shutdown()
            rel_srv.server_close()

    def test_session_token_roundtrip_and_tamper_rejection(self):
        tok = writings.create_session_token(now=1_700_000_000)
        self.assertTrue(writings.verify_session_token(tok, now=1_700_000_100))
        self.assertFalse(writings.verify_session_token(tok, now=1_700_000_000 + writings.SESSION_TTL_SECONDS + 1))
        body, sig = tok.split(".", 1)
        bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
        self.assertFalse(writings.verify_session_token(f"{body}.{bad_sig}", now=1_700_000_100))
        self.assertFalse(writings.verify_session_token("malformed"))

    def test_slug_and_filename_sanitization(self):
        self.assertEqual(writings.sanitize_slug("My Late-Night Mix Notes!"), "my-late-night-mix-notes")
        self.assertEqual(writings.sanitize_slug("../../../etc/passwd"), "etc-passwd")
        fname = writings.sanitize_filename("Studio Photo (Final).JPG")
        self.assertTrue(fname.endswith("-studio-photo-final.jpg"))
        with self.assertRaises(ValueError):
            writings.sanitize_filename("evil.exe")

    def test_frontmatter_roundtrip_and_newest_sort(self):
        meta = {
            "title": "Vocal Chain Notes",
            "slug": "vocal-chain-notes",
            "date": "2026-11-25",
            "updatedAt": "2026-11-25T10:00:00Z",
            "status": "published",
            "pinned": True,
            "tags": ["Mixing", "Vocals"],
            "summary": "Quick dry chain.",
            "coverImage": "writings/media/chain.jpg",
        }
        md = writings.serialize_post_markdown(meta, "## Step 1\n\nKeep stems **dry**.")
        parsed_meta, body = writings.parse_post_markdown(md)
        self.assertEqual(parsed_meta["title"], "Vocal Chain Notes")
        self.assertEqual(parsed_meta["tags"], ["Mixing", "Vocals"])
        self.assertTrue(parsed_meta["pinned"])
        self.assertIn("## Step 1", body)

        posts = [
            {"slug": "old", "date": "2026-01-01", "pinned": False},
            {"slug": "new", "date": "2026-11-25", "pinned": False},
            {"slug": "pin", "date": "2025-05-01", "pinned": True},
        ]
        ordered = writings.sort_posts_newest(posts)
        self.assertEqual([p["slug"] for p in ordered], ["pin", "new", "old"])

    def test_rss_generation_and_local_index_parse(self):
        posts, _ = writings.read_posts_index(prefer_live=False)
        self.assertIsInstance(posts, list)
        sample_posts = [
            {
                "slug": "studio-dispatch",
                "title": "Studio Dispatch",
                "date": "2026-11-25",
                "status": "published",
                "pinned": False,
                "summary": "Late-night vocal mix notes.",
            },
            {
                "slug": "secret-draft",
                "title": "Secret Draft",
                "date": "2026-11-25",
                "status": "draft",
                "pinned": False,
                "summary": "Should not appear in RSS.",
            },
        ]
        rss = writings.build_rss_feed(sample_posts)
        self.assertIn('<rss version="2.0">', rss)
        self.assertIn("studio-dispatch", rss)
        self.assertNotIn("secret-draft", rss)

    def test_geoblocker_blocks_cn_il_ru_ir_in_and_allows_others(self):
        for code in ("CN", "IL", "RU", "IR", "IN", "cn", "ru"):
            self.assertTrue(writings.is_country_blocked(code), f"Expected {code} to be blocked")
            self.assertEqual(writings.get_request_country({"X-Vercel-IP-Country": code}), code.upper())
        for allowed in ("AU", "US", "GB", "CA", "JP", "DE", ""):
            self.assertFalse(writings.is_country_blocked(allowed), f"Expected {allowed} to be allowed")

    def test_ecdh_p256_envelope_auth_replay_and_tamper_protection(self):
        test_pwd = "saint-gordon-test-passphrase-2026"
        test_hash = writings.compute_sha3_512(test_pwd)
        now = 1_750_000_000

        with mock.patch.dict(os.environ, {"WRITINGS_PASSWORD_HASH": test_hash, "GITHUB_TOKEN": "ghp_test_secret_123"}):
            ch = writings.create_login_challenge(now=now)
            self.assertEqual(len(ch["pub"]), 130)
            self.assertTrue(ch["pub"].startswith("04"))

            # Valid encrypted envelope succeeds once
            env = writings.seal_login_envelope_py(test_pwd, ch["nonce"], ch["exp"], ch["pub"])
            # Ensure plaintext password does NOT appear anywhere in envelope
            self.assertNotIn(test_pwd, json.dumps(env))
            self.assertNotIn(test_hash, json.dumps(env))

            ok, msg = writings.verify_login_envelope(
                ch["nonce"], ch["exp"], ch["sig"], env["epk"], env["ct"], env["tag"], now=now + 5
            )
            self.assertTrue(ok, msg)

            # Replaying the exact same valid envelope fails!
            ok_replay, _ = writings.verify_login_envelope(
                ch["nonce"], ch["exp"], ch["sig"], env["epk"], env["ct"], env["tag"], now=now + 6
            )
            self.assertFalse(ok_replay)

            # Submitting the SHA3-512 hash itself (pass-the-hash) FAILS!
            ch_pth = writings.create_login_challenge(now=now)
            env_pth = writings.seal_login_envelope_py(test_hash, ch_pth["nonce"], ch_pth["exp"], ch_pth["pub"])
            ok_pth, _ = writings.verify_login_envelope(
                ch_pth["nonce"], ch_pth["exp"], ch_pth["sig"], env_pth["epk"], env_pth["ct"], env_pth["tag"], now=now + 2
            )
            self.assertFalse(ok_pth)

            # Tampered ciphertext fails MAC check
            ch_t = writings.create_login_challenge(now=now)
            env_t = writings.seal_login_envelope_py(test_pwd, ch_t["nonce"], ch_t["exp"], ch_t["pub"])
            bad_ct = ("00" if not env_t["ct"].startswith("00") else "ff") + env_t["ct"][2:]
            ok_t, _ = writings.verify_login_envelope(
                ch_t["nonce"], ch_t["exp"], ch_t["sig"], env_t["epk"], bad_ct, env_t["tag"], now=now + 2
            )
            self.assertFalse(ok_t)

            # Expired challenge fails
            ch_exp = writings.create_login_challenge(now=now)
            env_exp = writings.seal_login_envelope_py(test_pwd, ch_exp["nonce"], ch_exp["exp"], ch_exp["pub"])
            ok_exp, _ = writings.verify_login_envelope(
                ch_exp["nonce"], ch_exp["exp"], ch_exp["sig"], env_exp["epk"], env_exp["ct"], env_exp["tag"],
                now=now + writings.CHALLENGE_TTL_SECONDS + 5,
            )
            self.assertFalse(ok_exp)

    def test_exponential_antibruteforce_lockout_and_signed_cookie_persistence(self):
        now = 1_760_000_000
        ip_key = "test-ip-key-bruteforce"
        writings.clear_failed_logins(ip_key)

        expected_schedule = [5, 15, 30, 120, 300, 900, 900]
        cookie_val = None
        for idx, expected_sec in enumerate(expected_schedule, start=1):
            fails, locked_until, timeout_sec, cookie_val = writings.record_failed_login(
                ip_key, cookie_val, now=now
            )
            self.assertEqual(fails, idx)
            self.assertEqual(timeout_sec, expected_sec)
            self.assertEqual(locked_until, now + expected_sec)

        writings.clear_failed_logins(ip_key)
        eff_fails, _, rem = writings.get_lockout_status(ip_key, cookie_val, now=now + 10)
        self.assertEqual(eff_fails, len(expected_schedule))
        self.assertEqual(rem, 890)
        self.assertEqual(writings.decode_lockout_cookie(cookie_val + "tamper", now=now), (0, 0))
        writings.clear_failed_logins(ip_key)

    def test_full_http_admin_crud_media_and_stealth_404_geoblocker(self):
        store = _FakeGitHubStore()
        test_pwd = "verify-full-admin-e2e-pass!"
        test_hash = writings.compute_sha3_512(test_pwd)

        server = HTTPServer(("127.0.0.1", 0), writings.handler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def http_call(method, path, body=None, headers=None):
            hdrs = dict(headers or {})
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    hdrs_out = dict(resp.headers.items())
                    hdrs_out["_set_cookies"] = resp.headers.get_all("Set-Cookie") or []
                    return resp.status, hdrs_out, resp.read()
            except urllib.error.HTTPError as err:
                try:
                    hdrs_out = dict(err.headers.items())
                    hdrs_out["_set_cookies"] = err.headers.get_all("Set-Cookie") or []
                    return err.code, hdrs_out, err.read()
                finally:
                    err.close()

        try:
            with mock.patch.dict(os.environ, {"WRITINGS_PASSWORD_HASH": test_hash, "GITHUB_TOKEN": "ghp_e2e_token_xyz"}), \
                 mock.patch.object(writings, "_github_request", side_effect=store.request):
                writings._IP_LOCKOUT_STATE.clear()
                writings._USED_NONCES.clear()

                # 1. Stealth 404 for geo-blocked countries (CN, IL, RU, IR, IN)
                for country in ("CN", "IL", "RU", "IR", "IN"):
                    st, _, raw = http_call("GET", "/api/writings?action=not_found", headers={"X-Vercel-IP-Country": country})
                    self.assertEqual(st, 404)
                    html = raw.decode("utf-8").lower()
                    self.assertIn("page not found", html)
                    self.assertNotIn("admin", html)
                    self.assertNotIn("region", html)
                    self.assertNotIn("restricted", html)
                    self.assertNotIn("geo-block", html)

                    st_sess, _, raw_sess = http_call("GET", "/api/writings?action=session", headers={"X-Vercel-IP-Country": country})
                    self.assertEqual(st_sess, 404)
                    self.assertNotIn("geo", raw_sess.decode("utf-8").lower())

                    st_post, _, _ = http_call("POST", "/api/writings", {"action": "login"}, headers={"X-Vercel-IP-Country": country})
                    self.assertEqual(st_post, 404)

                    # Public list still works worldwide
                    st_pub, _, _ = http_call("GET", "/api/writings?action=list", headers={"X-Vercel-IP-Country": country})
                    self.assertEqual(st_pub, 200)

                # 2. Plaintext login rejected with 400; cross-origin POST rejected with 403 (2E); unauth session scrubbed (3.1)
                st_pt, _, _ = http_call("POST", "/api/writings", {"action": "login", "password": test_pwd})
                self.assertEqual(st_pt, 400)

                st_csrf, _, _ = http_call(
                    "POST",
                    "/api/writings",
                    {"action": "logout"},
                    headers={"Origin": "https://evil.example"},
                )
                self.assertEqual(st_csrf, 403)

                st_sec_fetch, _, _ = http_call(
                    "POST",
                    "/api/writings",
                    {"action": "logout"},
                    headers={"Sec-Fetch-Site": "cross-site"},
                )
                self.assertEqual(st_sec_fetch, 403)

                st_unauth_sess, _, raw_unauth_sess = http_call("GET", "/api/writings?action=session")
                self.assertEqual(st_unauth_sess, 200)
                unauth_sess = json.loads(raw_unauth_sess)
                self.assertEqual(unauth_sess["authenticated"], False)
                self.assertNotIn("repo", unauth_sess)
                self.assertNotIn("branch", unauth_sess)
                self.assertNotIn("cloudConfigured", unauth_sess)
                self.assertNotIn("fails", unauth_sess)

                # 3. Valid ECDH P-256 encrypted login succeeds & sets HttpOnly session cookie
                st_ch, _, raw_ch = http_call("GET", "/api/writings?action=challenge")
                self.assertEqual(st_ch, 200)
                ch = json.loads(raw_ch)
                env = writings.seal_login_envelope_py(test_pwd, ch["nonce"], ch["exp"], ch["pub"])
                st_in, hdrs_in, raw_in = http_call("POST", "/api/writings", {
                    "action": "login",
                    "nonce": ch["nonce"],
                    "exp": ch["exp"],
                    "sig": ch["sig"],
                    **env,
                })
                self.assertEqual(st_in, 200, raw_in.decode("utf-8"))
                set_cookies = hdrs_in.get("_set_cookies") or []
                sess_raw = next((c for c in set_cookies if c.startswith("sg_writings_session=")), "")
                self.assertTrue(sess_raw, f"Missing session cookie in {set_cookies}")
                session_cookie = sess_raw.split(";", 1)[0]
                auth_hdr = {"Cookie": session_cookie}

                # 4. Upload PNG image via upload_media & verify live proxy serves exact PNG bytes
                png_1x1 = base64.b64decode(
                    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="
                )
                st_up, _, raw_up = http_call("POST", "/api/writings", {
                    "action": "upload_media",
                    "filename": "studio-test.png",
                    "dataBase64": "data:image/png;base64," + base64.b64encode(png_1x1).decode("ascii"),
                }, headers=auth_hdr)
                self.assertEqual(st_up, 200, raw_up.decode("utf-8"))
                up_data = json.loads(raw_up)
                media_name = up_data["media"]["filename"]
                media_path = up_data["media"]["path"]
                self.assertTrue(media_path.startswith("writings/media/"))

                st_m, hdrs_m, raw_m = http_call("GET", up_data["media"]["liveUrl"])
                self.assertEqual(st_m, 200)
                self.assertEqual(hdrs_m.get("Content-Type"), "image/png")
                self.assertIn("sandbox", hdrs_m.get("Content-Security-Policy", ""))
                self.assertEqual(raw_m, png_1x1)

                # 4b. Disguised XSS HTML uploaded as .png is rejected by magic-byte check (3.2)
                st_bad_media, _, _ = http_call("POST", "/api/writings", {
                    "action": "upload_media",
                    "filename": "evil.png",
                    "dataBase64": base64.b64encode(b"<script>alert(1)</script>").decode("ascii"),
                }, headers=auth_hdr)
                self.assertEqual(st_bad_media, 400)

                # 5. Create & publish post referencing uploaded image as cover & inline Markdown
                st_save, _, raw_save = http_call("POST", "/api/writings", {
                    "action": "save_post",
                    "title": "Studio Mix Breakdown",
                    "slug": "studio-mix-breakdown",
                    "date": "2026-11-25",
                    "tags": "Mixing, Studio",
                    "status": "published",
                    "pinned": False,
                    "summary": "Testing full post creation with images.",
                    "coverImage": media_path,
                    "body": f"## Signal Chain\n\n![Studio Test]({media_path})\n\nClean **dry** vocal bus.",
                }, headers=auth_hdr)
                self.assertEqual(st_save, 200, raw_save.decode("utf-8"))
                saved = json.loads(raw_save)
                self.assertEqual(len(saved["posts"]), 1)
                self.assertEqual(saved["post"]["slug"], "studio-mix-breakdown")

                # 6. Public reader sees published post & full body
                st_pub_list, _, raw_pub_list = http_call("GET", "/api/writings?action=list")
                self.assertEqual(st_pub_list, 200)
                self.assertEqual(len(json.loads(raw_pub_list)["posts"]), 1)

                st_pub_post, _, raw_pub_post = http_call("GET", "/api/writings?action=post&slug=studio-mix-breakdown")
                self.assertEqual(st_pub_post, 200)
                self.assertIn(media_path, json.loads(raw_pub_post)["body"])

                # 7. Toggle status to Draft -> isolated in writings/_drafts/, removed from public posts.json & posts/ (1B)
                st_tog, _, raw_tog = http_call("POST", "/api/writings", {
                    "action": "toggle_status",
                    "slug": "studio-mix-breakdown",
                }, headers=auth_hdr)
                self.assertEqual(st_tog, 200)
                self.assertEqual(json.loads(raw_tog)["post"]["status"], "draft")
                self.assertEqual(json.loads(store.files[writings.POSTS_INDEX_REL].decode("utf-8")), [])
                self.assertNotIn("writings/posts/studio-mix-breakdown.md", store.files)
                self.assertIn("writings/_drafts/studio-mix-breakdown.md", store.files)
                self.assertEqual(len(json.loads(store.files[writings.DRAFTS_INDEX_REL].decode("utf-8"))), 1)

                st_pub_draft, _, _ = http_call("GET", "/api/writings?action=post&slug=studio-mix-breakdown")
                self.assertEqual(st_pub_draft, 404)

                st_adm_list, _, raw_adm_list = http_call("GET", "/api/writings?action=admin_list", headers=auth_hdr)
                self.assertEqual(st_adm_list, 200)
                adm_data = json.loads(raw_adm_list)
                self.assertEqual(len(adm_data["posts"]), 1)
                self.assertEqual(len(adm_data["media"]), 1)

                # 8. Toggle pin
                st_pin, _, raw_pin = http_call("POST", "/api/writings", {
                    "action": "toggle_pin",
                    "slug": "studio-mix-breakdown",
                }, headers=auth_hdr)
                self.assertEqual(st_pin, 200)
                self.assertTrue(json.loads(raw_pin)["post"]["pinned"])

                # 9. Delete media & delete post
                st_dm, _, raw_dm = http_call("POST", "/api/writings", {
                    "action": "delete_media",
                    "filename": media_name,
                }, headers=auth_hdr)
                self.assertEqual(st_dm, 200)
                self.assertEqual(json.loads(raw_dm)["media"], [])

                st_dp, _, raw_dp = http_call("POST", "/api/writings", {
                    "action": "delete_post",
                    "slug": "studio-mix-breakdown",
                }, headers=auth_hdr)
                self.assertEqual(st_dp, 200)
                self.assertEqual(json.loads(raw_dp)["posts"], [])
                self.assertNotIn("writings/posts/studio-mix-breakdown.md", store.files)

                # 10. Logout clears session
                st_out, _, _ = http_call("POST", "/api/writings", {"action": "logout"}, headers=auth_hdr)
                self.assertEqual(st_out, 200)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
