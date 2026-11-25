import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api import writings


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

    def test_session_token_roundtrip_and_tamper_rejection(self):
        tok = writings.create_session_token(now=1_700_000_000)
        self.assertTrue(writings.verify_session_token(tok, now=1_700_000_100))
        # Expired token rejected
        self.assertFalse(writings.verify_session_token(tok, now=1_700_000_000 + writings.SESSION_TTL_SECONDS + 1))
        # Tampered signature rejected
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

    def test_zero_plaintext_challenge_response_and_replay_protection(self):
        now = 1_750_000_000
        ch = writings.create_login_challenge(now=now)
        good_proof = writings.compute_expected_login_proof(ch["nonce"], ch["exp"])
        # Valid proof succeeds once
        ok, msg = writings.verify_login_challenge_proof(
            ch["nonce"], ch["exp"], ch["sig"], good_proof, now=now + 5
        )
        self.assertTrue(ok, msg)
        # Replaying the exact same valid proof fails!
        ok_replay, _ = writings.verify_login_challenge_proof(
            ch["nonce"], ch["exp"], ch["sig"], good_proof, now=now + 6
        )
        self.assertFalse(ok_replay)
        # Expired challenge fails
        ch2 = writings.create_login_challenge(now=now)
        p2 = writings.compute_expected_login_proof(ch2["nonce"], ch2["exp"])
        ok_exp, _ = writings.verify_login_challenge_proof(
            ch2["nonce"], ch2["exp"], ch2["sig"], p2, now=now + writings.CHALLENGE_TTL_SECONDS + 5
        )
        self.assertFalse(ok_exp)
        # Wrong proof fails
        ch3 = writings.create_login_challenge(now=now)
        ok_bad, _ = writings.verify_login_challenge_proof(
            ch3["nonce"], ch3["exp"], ch3["sig"], "0" * 64, now=now + 1
        )
        self.assertFalse(ok_bad)

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

        # Simulate cold serverless container (wipe in-memory IP table) — signed cookie MUST still enforce lockout!
        writings.clear_failed_logins(ip_key)
        eff_fails, _, rem = writings.get_lockout_status(ip_key, cookie_val, now=now + 10)
        self.assertEqual(eff_fails, len(expected_schedule))
        self.assertEqual(rem, 890)

        # Tampered lockout cookie is ignored cleanly
        self.assertEqual(writings.decode_lockout_cookie(cookie_val + "tamper", now=now), (0, 0))
        writings.clear_failed_logins(ip_key)


if __name__ == "__main__":
    unittest.main()
