const encoder = new TextEncoder();
const COOKIE_NAME = "uvul_auth";
const SESSION_SECONDS = 8 * 60 * 60;
const json = (body, status = 200, extraHeaders = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders },
});
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const decode64url = (value) => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4)), c => c.charCodeAt(0));
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}
function equal(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
function getCookie(request) {
  const header = request.headers.get("cookie") || "";
  const entry = header.split(";").map(part => part.trim()).find(part => part.startsWith(`${COOKIE_NAME}=`));
  return entry ? entry.slice(COOKIE_NAME.length + 1) : "";
}
async function sessionName(request, secret) {
  const token = getCookie(request);
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra) return null;
  if (!equal(signature, await sign(payload, secret))) return null;
  try {
    const session = JSON.parse(new TextDecoder().decode(decode64url(payload)));
    if (typeof session.name !== "string" || !Number.isInteger(session.exp) || session.exp <= Math.floor(Date.now() / 1000)) return null;
    return session.name;
  } catch { return null; }
}
function cookieHeader(value, maxAge) {
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
function configured(password, secret) {
  return Boolean(password && secret && secret.length >= 32);
}
export default async (request, context) => {
  const url = new URL(request.url);
  const sharedPassword = Netlify.env.get("UVUL_SHARED_PASSWORD");
  const sessionSecret = Netlify.env.get("UVUL_SESSION_SECRET");
  const ready = configured(sharedPassword, sessionSecret);
  const path = url.pathname;

  if (path === "/__auth/login") {
    if (request.method !== "POST") return json({ error: "Método no permitido." }, 405, { allow: "POST" });
    if (!ready) return json({ error: "El acceso aún no está configurado en Netlify." }, 503);
    const origin = request.headers.get("origin");
    if (origin && origin !== url.origin) return json({ error: "Solicitud no válida." }, 403);
    let body;
    try { body = await request.json(); } catch { return json({ error: "Solicitud no válida." }, 400); }
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!name || name.length > 60 || !password || password.length > 256) return json({ error: "Escribe un nombre y una contraseña." }, 400);
    const [providedHash, expectedHash] = await Promise.all([
      crypto.subtle.digest("SHA-256", encoder.encode(password)),
      crypto.subtle.digest("SHA-256", encoder.encode(sharedPassword)),
    ]);
    const provided = b64url(providedHash), expected = b64url(expectedHash);
    if (!equal(provided, expected)) return json({ error: "Nombre o contraseña no válidos." }, 401);
    const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    const payload = b64url(encoder.encode(JSON.stringify({ name, exp: expires })));
    const token = `${payload}.${await sign(payload, sessionSecret)}`;
    return json({ ok: true }, 200, { "set-cookie": cookieHeader(token, SESSION_SECONDS) });
  }

  if (path === "/__auth/logout") {
    return json({ ok: true }, 200, { "set-cookie": cookieHeader("", 0) });
  }

  if (path === "/__auth/status") {
    if (!ready) return json({ error: "El acceso aún no está configurado en Netlify." }, 503);
    const name = await sessionName(request, sessionSecret);
    return name ? json({ name }) : json({ error: "Sesión no válida." }, 401);
  }

  if (path === "/login.html") {
    if (ready && await sessionName(request, sessionSecret)) return Response.redirect(new URL("/", url), 302);
    return context.next();
  }

  if (!ready) return new Response("Acceso temporalmente no disponible. El sitio requiere configuración segura.", { status: 503, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  if (!await sessionName(request, sessionSecret)) return new URL("/login.html", url);
  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set("cache-control", "private, no-store");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};
export const config = { path: "/*", onError: "fail" };
