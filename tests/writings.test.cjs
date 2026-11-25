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
  assert.match(html, /src="\/api\/writings\?action=media&amp;file=photo\.jpg"/);
  assert.match(html, /data-fallback-src="writings\/media\/photo\.jpg"/);
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

test("Web Crypto ECDH P-256 sealLoginEnvelope interoperates with Python api/writings.py", async () => {
  const { execFileSync } = require("node:child_process");
  const path = require("node:path");
  const root = path.resolve(__dirname, "..");
  const testPwd = "CrossLang-ECDH-P256-Test!🎵";

  // 1. Ask Python api/writings.py to mint a real P-256 challenge
  const pyChallenge = JSON.parse(
    execFileSync("python3", [
      "-c",
      `import json, os, sys; sys.path.insert(0, ${JSON.stringify(root)}); from api import writings; ` +
      `os.environ["GITHUB_TOKEN"]="test_secret_interop"; ` +
      `os.environ["WRITINGS_PASSWORD_HASH"]=writings.compute_sha3_512(${JSON.stringify(testPwd)}); ` +
      `print(json.dumps(writings.create_login_challenge(now=1750000000)))`,
    ], { encoding: "utf8" })
  );

  // 2. Seal envelope in JS using real Web Crypto ECDH P-256
  const env = await SaintCrypto.sealLoginEnvelope(testPwd, pyChallenge.nonce, pyChallenge.exp, pyChallenge.pub);
  assert.equal(env.epk.length, 130);
  assert.equal(env.ct.length, 512);
  assert.equal(env.tag.length, 64);
  assert.equal(JSON.stringify(env).includes(testPwd), false);

  // 3. Ask Python api/writings.py to decrypt & verify JS-sealed envelope
  const pyVerify = JSON.parse(
    execFileSync("python3", [
      "-c",
      `import json, os, sys; sys.path.insert(0, ${JSON.stringify(root)}); from api import writings; ` +
      `os.environ["GITHUB_TOKEN"]="test_secret_interop"; ` +
      `os.environ["WRITINGS_PASSWORD_HASH"]=writings.compute_sha3_512(${JSON.stringify(testPwd)}); ` +
      `ch=${JSON.stringify(pyChallenge)}; env=${JSON.stringify(env)}; ` +
      `ok, msg = writings.verify_login_envelope(ch["nonce"], ch["exp"], ch["sig"], env["epk"], env["ct"], env["tag"], now=1750000005); ` +
      `print(json.dumps({"ok": ok, "msg": msg}))`,
    ], { encoding: "utf8" })
  );
  assert.equal(pyVerify.ok, true, pyVerify.msg);
});
