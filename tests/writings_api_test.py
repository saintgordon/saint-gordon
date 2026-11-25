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

    def test_local_starter_post_and_rss_generation(self):
        posts, _ = writings.read_posts_index(prefer_live=False)
        self.assertGreaterEqual(len(posts), 1)
        self.assertEqual(posts[0]["slug"], "welcome-to-writings")
        meta, body = writings.read_post_markdown("welcome-to-writings", prefer_live=False)
        self.assertEqual(meta["title"], "Welcome to Saint Gordon Writings")
        self.assertIn("Writings", body)
        rss = writings.build_rss_feed(posts)
        self.assertIn("<rss version=\"2.0\">", rss)
        self.assertIn("welcome-to-writings", rss)


if __name__ == "__main__":
    unittest.main()
