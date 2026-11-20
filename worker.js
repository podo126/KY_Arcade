// Basic Auth gate for the KY Arcade static site.
// - /share, /share.html: public (no auth)
// - everything else: requires Basic Auth (SITE_USER / SITE_PASSWORD)
// - if SITE_PASSWORD is not set, every non-public request is blocked

const PUBLIC_PATHS = new Set(["/share", "/share.html"]);
const encoder = new TextEncoder();

// Hash both sides first so timingSafeEqual always gets equal-length buffers
// (it throws on length mismatch, which would otherwise leak length info).
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

function parseBasicAuth(header) {
  if (!header) return null;
  const [scheme, encoded] = header.split(" ");
  if (!scheme || scheme.toLowerCase() !== "basic" || !encoded) return null;
  let decoded;
  try {
    decoded = new TextDecoder().decode(
      Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))
    );
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx === -1) return null;
  return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
}

function unauthorized() {
  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="KY Arcade", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (PUBLIC_PATHS.has(pathname)) {
      return env.ASSETS.fetch(request);
    }

    const expectedPass = env.SITE_PASSWORD;
    if (!expectedPass) {
      return new Response("Site is locked (SITE_PASSWORD not configured)", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }
    const expectedUser = env.SITE_USER || "ky";

    const creds = parseBasicAuth(request.headers.get("Authorization"));
    if (!creds) return unauthorized();

    // Evaluate both comparisons (no short-circuit) to keep timing uniform.
    const [userOk, passOk] = await Promise.all([
      safeEqual(creds.user, expectedUser),
      safeEqual(creds.pass, expectedPass),
    ]);
    if (!(userOk && passOk)) return unauthorized();

    const response = await env.ASSETS.fetch(request);
    // Keep authenticated content out of shared caches.
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "private, no-store");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};
