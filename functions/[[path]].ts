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

function buildUpstreamHeaders(request: Request, apiKey: string): Headers {
  const headers = new Headers(request.headers);

  // Remove hop-by-hop headers that should not be forwarded.
  for (const header of HOP_BY_HOP_HEADERS) headers.delete(header);

  // Do not forward internal routing headers.
  headers.delete(AUTH_HEADER);

  // Always set Authorization from the environment to avoid leaking client keys.
  headers.set("authorization", `Bearer ${apiKey}`);

  // Ensure the upstream origin is used for Host.
  headers.set("host", new URL(OPENAI_ORIGIN).host);

  return headers;
}

export async function onRequest({ request, env }: { request: Request; env: Record<string, string> }) {
  const requiredToken = env.PROXY_TOKEN;
  if (!requiredToken) {
    return new Response("Missing PROXY_TOKEN", { status: 500 });
  }

  const providedToken = request.headers.get(AUTH_HEADER);
  if (providedToken !== requiredToken) {
    return new Response("Unauthorized", { status: 401 });
  }

  const apiKey = env.OPENAI_API_KEY;
  if (!apiKey) {
    return new Response("Missing OPENAI_API_KEY", { status: 500 });
  }

  const requestUrl = new URL(request.url);
  const upstreamUrl = buildUpstreamUrl(requestUrl);

  const init: RequestInit = {
    method: request.method,
    headers: buildUpstreamHeaders(request, apiKey),
  };

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
