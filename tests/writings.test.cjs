const test = require("node:test");
const assert = require("node:assert/strict");
const MD = require("../js/writings-markdown.js");

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
