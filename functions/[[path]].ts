// functions/path.ts

const OPENAI_ORIGIN = "https://api.openai.com";
const AUTH_HEADER = "x-proxy-token";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function buildUpstreamUrl(requestUrl: URL): string {
  // Preserve the full path/query; this allows /v1/... and other endpoints.
  return `${OPENAI_ORIGIN}${requestUrl.pathname}${requestUrl.search}`;
}

function buildUpstreamHeaders(request: Request, apiKey?: string): Headers {
  const headers = new Headers(request.headers);

  // Remove hop-by-hop headers that should not be forwarded.
  for (const header of HOP_BY_HOP_HEADERS) headers.delete(header);

  // Do not forward internal routing header.
  headers.delete(AUTH_HEADER);

  // Keep the client's OpenAI API key if provided; otherwise fallback to env OPENAI_API_KEY.
  // If neither is present, reject.
  const auth = headers.get("authorization");
  if (!auth) {
    if (!apiKey) throw new Error("Missing Authorization (client) and OPENAI_API_KEY (env)");
    headers.set("authorization", `Bearer ${apiKey}`);
  }

  // NOTE:
  // Do NOT force `host` here. In Cloudflare Workers/Pages, Host is controlled by the URL you fetch.
  // Setting it can be ignored or cause issues depending on the platform.

  return headers;
}

export async function onRequest({
  request,
  env,
}: {
  request: Request;
  env: Record<string, string>;
}) {
  const requiredToken = env.PROXY_TOKEN;
  if (!requiredToken) {
    return new Response("Missing PROXY_TOKEN", { status: 500 });
  }

  const providedToken = request.headers.get(AUTH_HEADER);
  if (providedToken !== requiredToken) {
    return new Response("Unauthorized", { status: 401 });
  }

  // Optional if client provides Authorization; used only as fallback
  const apiKey = env.OPENAI_API_KEY;

  const requestUrl = new URL(request.url);
  const upstreamUrl = buildUpstreamUrl(requestUrl);

  let upstreamHeaders: Headers;
  try {
    upstreamHeaders = buildUpstreamHeaders(request, apiKey);
  } catch (e: any) {
    return new Response(e?.message ?? "Missing authorization", { status: 401 });
  }

  const init: RequestInit = {
    method: request.method,
    headers: upstreamHeaders,
    // `redirect: "manual"` can be set if you want to avoid automatic redirects
  };

  // Forward body for non-GET/HEAD
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
  }

  const upstreamResponse = await fetch(upstreamUrl, init);

  // Pass through status/body/headers as-is (minus hop-by-hop headers).
  const responseHeaders = new Headers(upstreamResponse.headers);
  for (const header of HOP_BY_HOP_HEADERS) responseHeaders.delete(header);

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
}