const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const MD = require("../js/writings-markdown.js");
const SaintCrypto = require("../js/sha3-512.js");

test("renders headings, formatting, blockquotes, lists, and escapes XSS", () => {
  const input = [
    "## Studio Dispatch",
    "",
    "This is **bold**, *italic*, `code`, and <script>alert(1)</script>.",
    "",
    "> Raw sound first.",
    "",
    "- First item",
    "- Second item",
    "",
    "[Safe Link](https://saintgordon.vercel.app) and [Bad Link](javascript:alert(1))",
  ].join("\n");

  const html = MD.renderMarkdown(input);
  assert.match(html, /<h2>Studio Dispatch<\/h2>/);
  assert.match(html, /<strong>bold<\/strong>/);
  assert.match(html, /<em>italic<\/em>/);
  assert.match(html, /<code>code<\/code>/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /<blockquote><p>Raw sound first\.<\/p><\/blockquote>/);
  assert.match(html, /<ul><li>First item<\/li><li>Second item<\/li><\/ul>/);
  assert.match(html, /href="https:\/\/saintgordon\.vercel\.app\/"/);
  assert.doesNotMatch(html, /javascript:/);
});

test("auto-embeds YouTube, Vimeo, SoundCloud, direct video, and local media fallbacks", () => {
  const md = [
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "",
    "https://vimeo.com/123456789",
    "",
    "https://soundcloud.com/ceannairefr/faith",
    "",
    "![Studio clip](writings/media/demo.mp4)",
    "",
    "![Xerox still](writings/media/photo.jpg)",
  ].join("\n");

  const html = MD.renderMarkdown(md);
  assert.match(html, /youtube-nocookie\.com\/embed\/dQw4w9WgXcQ/);
  assert.match(html, /player\.vimeo\.com\/video\/123456789/);
  assert.match(html, /w\.soundcloud\.com\/player/);
  assert.match(html, /<video class="writing-video"/);
  assert.match(html, /data-fallback-src="\/api\/writings\?action=media&amp;file=photo\.jpg"/);
});

test("slugify, stripMarkdown, and reading time work cleanly", () => {
  assert.equal(MD.slugify("Late Night Vocal Chain #2!"), "late-night-vocal-chain-2");
  assert.equal(MD.stripMarkdown("## Hello **World** [link](https://example.com)"), "Hello World link");
  assert.equal(MD.estimateReadingTime("word ".repeat(420)), 2);
});

test("pure-JS FIPS 202 SHA3-512 and zero-plaintext login proof match Node OpenSSL bit-for-bit", async () => {
  const vectors = ["", "abc", "saint-gordon-test", "x".repeat(72), "x".repeat(150), "Café 🎵"];
  for (const v of vectors) {
    const expected = crypto.createHash("sha3-512").update(v, "utf8").digest("hex");
    assert.equal(SaintCrypto.sha3_512(v), expected);
  }
  const nonce = "a".repeat(64);
  const exp = 1750000060;
  const proof = await SaintCrypto.createLoginProof("test-passphrase", nonce, exp);
  const pwdHash = crypto.createHash("sha3-512").update("test-passphrase", "utf8").digest("hex");
  const expectedProof = crypto.createHmac("sha256", pwdHash).update(`${nonce}:${exp}`).digest("hex");
  assert.equal(proof, expectedProof);
});
