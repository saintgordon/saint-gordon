/**
 * Saint Gordon Collective — Custom Vercel Edge WAF (Routing Middleware)
 *
 * Runs at the Edge before static assets or serverless Python lambdas execute:
 *  1. HTTP Method Firewall (GET/HEAD/OPTIONS globally; POST strictly on /api/writings)
 *  2. URL Length, Null-Byte, Path-Traversal & Double-Encoding Inspection
 *  3. Exploit, Dotfile, Legacy Backup & Internal Directory Probe Blocking (Stealth 404)
 *  4. Offensive Scanner & CLI Automation User-Agent Blocking
 *  5. Query-String Injection Filter (XSS / SQLi / SSRF / JNDI signatures)
 *  6. API Cache-Busting Stripper & Parameter Allowlist (protects GitHub & SoundCloud quotas)
 *  7. Strict AU-Only + Loopback (127.0.0.1 / ::1) Geolock on /admin & Admin API Actions
 *  8. Edge Sliding-Window Auth Rate Limiter & Pre-Auth 4 KB POST Body Gate
 */

const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST"]);

const ADMIN_API_ACTIONS = new Set([
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
]);

const PUBLIC_API_ACTIONS = new Set(["list", "post", "media"]);

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MEDIA_FILE_RE = /^[a-zA-Z0-9._-]+\.(?:jpe?g|png|webp|gif|mp4|webm|mov|mp3|wav)$/i;

const SCANNER_UA_RE =
  /\b(?:sqlmap|nikto|nuclei|ffuf|gobuster|feroxbuster|dirbuster|dirsearch|wfuzz|masscan|zgrab|nmap|acunetix|nessus|openvas|wpscan|burpcollaborator|interactsh|havij|commix)\b/i;

const CLI_BOT_UA_RE =
  /^(?:curl|wget|python-requests|python-httpx|aiohttp|go-http-client|libwww-perl|scrapy|java|okhttp|axios)\b/i;

const BLOCKED_PATH_RE =
  /(?:^\/(?:\.(?:env|git|aws|ssh|DS_Store|vercel|htaccess|htpasswd)|wp-(?:admin|login|content|includes)|xmlrpc\.php|phpmyadmin|pma|adminer|actuator|cgi-bin|vendor\/phpunit|server-status|writings\/_drafts|dist(?:\/|$))|\.(?:php\d?|phtml|asp|aspx|jsp|cgi|env|sql|bak|old|orig|swp|pyc)$)/i;

const INJECTION_QUERY_RE =
  /(?:<\s*script\b|javascript\s*:|vbscript\s*:|on(?:error|load|mouseover|focus)\s*=|\bunion\s+(?:all\s+)?select\b|\binformation_schema\b|\$\{jndi:|(?:file|gopher|dict|ldap):\/\/)/i;

const MAX_URL_LENGTH = 1024;
const MAX_UNAUTH_POST_BYTES = 4096;

// Bounded per-isolate sliding-window rate state for admin/auth bursts
const _EDGE_RATE = new Map();
const EDGE_AUTH_WINDOW_MS = 60_000;
const EDGE_AUTH_MAX_BURST = 20;

const STEALTH_404_HTML =
  "<!doctype html><html lang='en'><head><meta charset='utf-8'/>" +
  "<meta name='viewport' content='width=device-width,initial-scale=1'/>" +
  "<meta name='robots' content='noindex,nofollow'/>" +
  "<title>404 — Page Not Found | Saint Gordon Collective</title>" +
  "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f2f2f2;color:#101010;" +
  "font-family:'Courier New',monospace;padding:24px;}main{max-width:520px;background:#fff;border:1px solid #101010;" +
  "padding:36px;box-shadow:7px 7px 0 #101010;}h1{font-family:Georgia,serif;margin:12px 0 10px;font-size:30px;}" +
  "p{font-family:Arial,sans-serif;line-height:1.6;color:#303030;}a{color:#101010;font-weight:700;}</style></head>" +
  "<body><main><div>HTTP 404 // NOT FOUND</div><h1>Page Not Found.</h1>" +
  "<p>The page you are looking for does not exist or has been moved.</p>" +
  "<p><a href='/'>← Return Home</a></p></main></body></html>";

function stealth404Response(asJson) {
  if (asJson) {
    return new Response(JSON.stringify({ error: "Not found." }), {
      status: 404,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
      },
    });
  }
  return new Response(STEALTH_404_HTML, {
    status: 404,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function jsonError(status, message, extraHeaders) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: Object.assign(
      {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      },
      extraHeaders || {}
    ),
  });
}

function passThrough() {
  return new Response(null, {
    headers: { "x-middleware-next": "1" },
  });
}

function rewriteTo(targetUrl) {
  return new Response(null, {
    headers: { "x-middleware-rewrite": targetUrl.toString() },
  });
}

export function isLoopbackAddress(ip) {
  const clean = String(ip || "").trim().toLowerCase();
  if (!clean) return false;
  if (clean === "127.0.0.1" || clean === "::1" || clean === "[::1]" || clean === "localhost") {
    return true;
  }
  if (clean.startsWith("127.") || clean.startsWith("::ffff:127.")) {
    return true;
  }
  return false;
}

export function extractTrustedClientIp(headers, urlHostname) {
  const isVercelEdge = Boolean(headers.get("x-vercel-id"));
  const realIp = (
    headers.get("x-real-ip") ||
    headers.get("x-vercel-forwarded-for") ||
    headers.get("cf-connecting-ip") ||
    ""
  ).trim();

  if (realIp) {
    const parts = realIp.split(",");
    return parts[parts.length - 1].trim();
  }

  // Only fall back to right-most XFF or local URL hostname when NOT on Vercel Edge
  if (!isVercelEdge) {
    const xff = (headers.get("x-forwarded-for") || "").trim();
    if (xff) {
      const parts = xff.split(",");
      return parts[parts.length - 1].trim();
    }
    if (isLoopbackAddress(urlHostname)) {
      return "127.0.0.1";
    }
  }
  return "";
}

export function isAdminGeoOrLoopbackAllowed(headers, urlHostname) {
  const country = (
    headers.get("x-vercel-ip-country") ||
    headers.get("cf-ipcountry") ||
    ""
  )
    .trim()
    .toUpperCase();

  // Explicit country header present: strictly allow Australia (AU) ONLY
  if (country) {
    return country === "AU";
  }

  // No country header: allow ONLY trusted loopback (127.0.0.1 / ::1) so the server can talk to itself
  const clientIp = extractTrustedClientIp(headers, urlHostname);
  return isLoopbackAddress(clientIp);
}

function checkEdgeAuthBurst(ipKey, nowMs) {
  if (_EDGE_RATE.size > 2048) {
    for (const [k, v] of _EDGE_RATE) {
      if (nowMs - v.start > EDGE_AUTH_WINDOW_MS) _EDGE_RATE.delete(k);
    }
    if (_EDGE_RATE.size > 2048) _EDGE_RATE.clear();
  }
  const cur = _EDGE_RATE.get(ipKey);
  if (!cur || nowMs - cur.start > EDGE_AUTH_WINDOW_MS) {
    _EDGE_RATE.set(ipKey, { start: nowMs, count: 1 });
    return true;
  }
  cur.count += 1;
  return cur.count <= EDGE_AUTH_MAX_BURST;
}

function hasSessionCookie(cookieHeader) {
  if (!cookieHeader) return false;
  return /(?:^|;\s*)(?:__Host-)?sg_writings_session=[^;\s]+/.test(cookieHeader);
}

export default function middleware(request) {
  const rawUrl = request.url || "";
  if (rawUrl.length > MAX_URL_LENGTH) {
    return stealth404Response(false);
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch (_) {
    return stealth404Response(false);
  }

  const method = (request.method || "GET").toUpperCase();
  const pathname = url.pathname || "/";
  const isApi = pathname.startsWith("/api/");

  // 1. HTTP Method Firewall
  if (!ALLOWED_METHODS.has(method)) {
    return jsonError(405, "Method not allowed.", { Allow: "GET, HEAD, OPTIONS, POST" });
  }
  if (method === "POST" && pathname !== "/api/writings") {
    return stealth404Response(isApi);
  }

  // 2. Raw Path Traversal, Null-Byte & Double-Encoding Check
  const rawPathAndQuery = pathname + (url.search || "");
  if (
    rawPathAndQuery.includes("\0") ||
    /(?:%00|%0d|%0a|\.\.\/|\/?\.\.\\|%2e%2e|%252e|%5c|%c0%af)/i.test(rawPathAndQuery)
  ) {
    return stealth404Response(isApi);
  }

  // 3. Exploit, Dotfile & Internal Directory Probe Trap
  if (BLOCKED_PATH_RE.test(pathname)) {
    return stealth404Response(isApi);
  }

  // 4. Offensive Scanner User-Agent Block
  const ua = request.headers.get("user-agent") || "";
  if (ua && SCANNER_UA_RE.test(ua)) {
    return stealth404Response(isApi);
  }

  // 5. Query-String Payload Inspection (XSS / SQLi / SSRF / JNDI)
  if (url.search) {
    let decodedSearch = url.search;
    try {
      decodedSearch = decodeURIComponent(url.search);
    } catch (_) {
      return stealth404Response(isApi);
    }
    if (INJECTION_QUERY_RE.test(decodedSearch)) {
      return stealth404Response(isApi);
    }
  }

  const isAdminPage =
    pathname === "/admin" ||
    pathname === "/admin.html" ||
    pathname.startsWith("/admin/");

  const actionParam = (url.searchParams.get("action") || (pathname === "/api/writings" ? "list" : ""))
    .trim()
    .toLowerCase();

  const isWritingsApi = pathname === "/api/writings";
  const isAdminApiRequest =
    isWritingsApi && (method === "POST" || ADMIN_API_ACTIONS.has(actionParam));

  // 6. Strict AU-Only + Loopback Geolock & CLI Bot Shield on /admin and Admin API
  if (isAdminPage || isAdminApiRequest) {
    if (actionParam === "not_found" || actionParam === "geo_blocked") {
      return stealth404Response(false);
    }

    if (!isAdminGeoOrLoopbackAllowed(request.headers, url.hostname)) {
      return stealth404Response(isApi);
    }

    const clientIp = extractTrustedClientIp(request.headers, url.hostname);
    if (!isLoopbackAddress(clientIp)) {
      // Block headless CLI bots from probing /admin even from AU IPs
      if (!ua || CLI_BOT_UA_RE.test(ua)) {
        return stealth404Response(isApi);
      }
      // Edge burst limiter on challenge/login/admin endpoints
      if (!checkEdgeAuthBurst(clientIp || "au-anon", Date.now())) {
        return jsonError(429, "Too many requests. Please wait a moment.", { "Retry-After": "30" });
      }
    }

    // Pre-Auth 4 KB POST body gate at the Edge
    if (method === "POST" && !hasSessionCookie(request.headers.get("cookie") || "")) {
      const len = Number(request.headers.get("content-length") || "0");
      if (len > MAX_UNAUTH_POST_BYTES) {
        return jsonError(413, "Payload too large.");
      }
    }

    return passThrough();
  }

  // 7. /api/releases Cache-Busting Stripper (forces shared Edge cache hit)
  if (pathname === "/api/releases") {
    if (url.search) {
      const cleanUrl = new URL(url.toString());
      cleanUrl.search = "";
      return rewriteTo(cleanUrl);
    }
    return passThrough();
  }

  // 8. Public GET /api/writings Parameter Allowlist & Format Validation
  if (isWritingsApi && (method === "GET" || method === "HEAD")) {
    if (!PUBLIC_API_ACTIONS.has(actionParam)) {
      return jsonError(400, "Invalid action.");
    }

    const cleanParams = new URLSearchParams();
    cleanParams.set("action", actionParam);

    if (actionParam === "post") {
      const slug = (url.searchParams.get("slug") || "").trim().toLowerCase();
      if (!slug || slug.length > 80 || !SLUG_RE.test(slug)) {
        return jsonError(404, "Post not found.", {
          "Cache-Control": "public, max-age=30, s-maxage=60",
        });
      }
      cleanParams.set("slug", slug);
    } else if (actionParam === "media") {
      const file = (url.searchParams.get("file") || "").trim();
      if (!file || file.length > 120 || file.includes("..") || !MEDIA_FILE_RE.test(file)) {
        return jsonError(404, "Media file not found.", {
          "Cache-Control": "public, max-age=30, s-maxage=60",
        });
      }
      cleanParams.set("file", file);
    }

    const canonicalSearch = "?" + cleanParams.toString();
    if (url.search !== canonicalSearch) {
      const cleanUrl = new URL(url.toString());
      cleanUrl.search = canonicalSearch;
      return rewriteTo(cleanUrl);
    }
  }

  return passThrough();
}

export const config = {
  runtime: "edge",
  matcher: ["/((?!assets/fonts/|assets/icons/|favicon\\.ico).*)"],
};
