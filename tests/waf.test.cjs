const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

async function loadWaf() {
  return import(pathToFileURL(path.resolve(__dirname, "../middleware.js")).href);
}

function makeReq(urlPath, { method = "GET", headers = {} } = {}) {
  return new Request(urlPath.startsWith("http") ? urlPath : "https://saintgordon.vercel.app" + urlPath, {
    method,
    headers,
  });
}

test("Edge WAF allows public pages and strips cache-busting query params on APIs", async () => {
  const { default: middleware } = await loadWaf();

  const home = middleware(makeReq("/index.html", { headers: { "user-agent": "Mozilla/5.0" } }));
  assert.equal(home.headers.get("x-middleware-next"), "1");

  // /api/releases strips cache-busting query params so CDN edge cache is shared
  const rel = middleware(makeReq("/api/releases?cb=99999&utm_source=spam"));
  assert.equal(rel.headers.get("x-middleware-rewrite"), "https://saintgordon.vercel.app/api/releases");

  // /api/writings?action=post&slug=valid-slug&cb=123 canonicalizes query string
  const postOk = middleware(makeReq("/api/writings?cb=123&action=post&slug=the-pultec-low-end-trick"));
  assert.equal(
    postOk.headers.get("x-middleware-rewrite"),
    "https://saintgordon.vercel.app/api/writings?action=post&slug=the-pultec-low-end-trick"
  );

  // Invalid random/malformed slug rejected at Edge with cached 404 before touching GitHub API
  const badSlug = middleware(makeReq("/api/writings?action=post&slug=INVALID!!SLUG"));
  assert.equal(badSlug.status, 404);
  assert.match(badSlug.headers.get("cache-control") || "", /s-maxage=60/);
});

test("Edge WAF blocks scanners, exploit paths, path traversal, and disallowed methods", async () => {
  const { default: middleware } = await loadWaf();

  // Disallowed HTTP methods
  const traceResp = middleware(makeReq("/index.html", { method: "DELETE" }));
  assert.equal(traceResp.status, 405);

  // POST only allowed on /api/writings
  const badPost = middleware(makeReq("/index.html", { method: "POST" }));
  assert.equal(badPost.status, 404);

  // Exploit & dotfile probes
  for (const probe of ["/.env", "/.git/config", "/wp-admin/install.php", "/phpmyadmin", "/writings/_drafts/index.json", "/dist/admin.html"]) {
    const r = middleware(makeReq(probe, { headers: { "user-agent": "Mozilla/5.0" } }));
    assert.equal(r.status, 404, `Expected stealth 404 for ${probe}`);
  }

  // Offensive scanner User-Agent
  const scanner = middleware(makeReq("/writings", { headers: { "user-agent": "sqlmap/1.8" } }));
  assert.equal(scanner.status, 404);

  // Path traversal & XSS/SQLi query payloads
  const trav = middleware(makeReq("/writings?q=%2e%2e%2fetc%2fpasswd"));
  assert.equal(trav.status, 404);
  const sqli = middleware(makeReq("/writings?q=1+UNION+SELECT+*+FROM+information_schema.tables"));
  assert.equal(sqli.status, 404);
});

test("Edge WAF geolocks /admin and Admin API strictly to AU or loopback (127.0.0.1 / ::1)", async () => {
  const { default: middleware } = await loadWaf();
  const browserUa = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36";

  // Non-AU countries (US, GB, CN, DE, SG) -> Stealth 404!
  for (const cc of ["US", "GB", "CN", "RU", "DE", "SG", "JP"]) {
    const rPage = middleware(
      makeReq("/admin", {
        headers: {
          "x-vercel-id": "syd1::123",
          "x-vercel-ip-country": cc,
          "x-real-ip": "203.0.113.50",
          "user-agent": browserUa,
        },
      })
    );
    assert.equal(rPage.status, 404, `Expected /admin 404 for country ${cc}`);

    const rApi = middleware(
      makeReq("/api/writings?action=session", {
        headers: {
          "x-vercel-id": "syd1::123",
          "x-vercel-ip-country": cc,
          "x-real-ip": "203.0.113.50",
          "user-agent": browserUa,
        },
      })
    );
    assert.equal(rApi.status, 404, `Expected admin API 404 for country ${cc}`);
  }

  // Spoofing X-Forwarded-For: 127.0.0.1 from US on Vercel Edge -> STILL 404!
  const spoofLoopback = middleware(
    makeReq("/admin", {
      headers: {
        "x-vercel-id": "iad1::999",
        "x-vercel-ip-country": "US",
        "x-forwarded-for": "127.0.0.1",
        "x-real-ip": "198.51.100.77",
        "user-agent": browserUa,
      },
    })
  );
  assert.equal(spoofLoopback.status, 404);

  // Real Australian browser -> Allowed!
  const auOk = middleware(
    makeReq("/admin", {
      headers: {
        "x-vercel-id": "syd1::456",
        "x-vercel-ip-country": "AU",
        "x-real-ip": "203.0.113.88",
        "user-agent": browserUa,
      },
    })
  );
  assert.equal(auOk.headers.get("x-middleware-next"), "1");

  // CLI bot (curl) from AU -> Blocked with stealth 404!
  const auCurl = middleware(
    makeReq("/admin", {
      headers: {
        "x-vercel-id": "syd1::456",
        "x-vercel-ip-country": "AU",
        "x-real-ip": "203.0.113.88",
        "user-agent": "curl/8.6.0",
      },
    })
  );
  assert.equal(auCurl.status, 404);

  // Loopback (127.0.0.1 / ::1) talking to itself -> Allowed!
  const loop1 = middleware(makeReq("http://127.0.0.1:8789/admin.html"));
  assert.equal(loop1.headers.get("x-middleware-next"), "1");
  const loop2 = middleware(
    makeReq("/api/writings?action=session", {
      headers: { "x-real-ip": "::1" },
    })
  );
  assert.equal(loop2.headers.get("x-middleware-next"), "1");

  // Unauthenticated >4 KB POST body blocked with 413 at Edge
  const hugePreAuth = middleware(
    makeReq("http://127.0.0.1:8789/api/writings", {
      method: "POST",
      headers: { "content-length": "50000" },
    })
  );
  assert.equal(hugePreAuth.status, 413);
});
