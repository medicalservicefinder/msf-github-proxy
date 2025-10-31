import jwt from "jsonwebtoken";

// Exchange App JWT → short-lived installation token
async function getInstallationToken(appId, installationId, pem) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iat: now - 60, exp: now + 9 * 60, iss: appId };
  const appJwt = jwt.sign(payload, pem, { algorithm: "RS256" });

  const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "msf-github-proxy"
    }
  });
  if (!res.ok) throw new Error(`token_exchange_failed ${res.status} ${await res.text()}`);
  const json = await res.json();
  return json.token;
}

function isAllowed(owner, repo) {
  const allow = (process.env.ALLOWED_REPOS || "").split(",").map(s => s.trim());
  return allow.includes(`${owner}/${repo}`);
}

export default async function handler(req, res) {
  try {
    const { method } = req;
    const u = new URL(req.url, `http://${req.headers.host}`);
    // Pattern: /api/github-proxy/repos/:owner/:repo/contents/:path
    const m = u.pathname.match(/^\/api\/github-proxy\/repos\/([^/]+)\/([^/]+)\/contents\/(.+)$/);
    if (!m) return res.status(400).json({ error: "bad_path" });

    const [, owner, repo, path] = m;

    if (!isAllowed(owner, repo)) {
      return res.status(403).json({ error: "repo_not_allowed" });
    }

    const appId = process.env.GITHUB_APP_ID;
    const instId = process.env.GITHUB_INSTALLATION_ID;
    const pem = process.env.GITHUB_APP_PRIVATE_KEY;
    if (!appId || !instId || !pem) {
      return res.status(500).json({ error: "missing_env" });
    }

    const token = await getInstallationToken(appId, instId, pem);

    const ghUrl = new URL(`https://api.github.com/repos/${owner}/${repo}/contents/${path}`);
    for (const [k, v] of u.searchParams) ghUrl.searchParams.set(k, v);

    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "msf-github-proxy"
    };

    let ghRes;
    if (method === "GET") {
      ghRes = await fetch(ghUrl, { headers });
    } else if (method === "PUT") {
      const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});
      ghRes = await fetch(ghUrl, {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body
      });
    } else {
      return res.status(405).json({ error: "method_not_allowed" });
    }

    const text = await ghRes.text();
    res.status(ghRes.status)
       .setHeader("Content-Type", ghRes.headers.get("content-type") || "application/json")
       .send(text);
  } catch (e) {
    res.status(500).json({ error: "proxy_error", message: String(e) });
  }
}
