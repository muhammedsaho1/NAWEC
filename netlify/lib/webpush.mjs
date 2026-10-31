// Minimal Web Push (VAPID + aes128gcm, RFC 8291/8292) using only the Web Crypto API.
// Works on Cloudflare Workers/Pages and Node 18+, with no npm package.
const te = new TextEncoder();
const b64u = (buf) => {
  let s = ""; const b = new Uint8Array(buf);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (s) => {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/"); s += "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const hkdf = async (salt, ikm, info, bytes) => {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, bytes * 8));
};

// Same key format as the web-push npm package (base64url): publicKey = 65-byte point, privateKey = 32-byte d.
export async function generateVAPIDKeys() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return { publicKey: b64u(concat(new Uint8Array([4]), unb64u(jwk.x), unb64u(jwk.y))), privateKey: jwk.d };
}

async function vapidAuth(endpoint, vapid) {
  const pub = unb64u(vapid.publicKey);
  const jwk = { kty: "EC", crv: "P-256", d: vapid.privateKey, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), ext: true };
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const header = b64u(te.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(te.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: vapid.subject })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, te.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64u(sig)}, k=${vapid.publicKey}`;
}

async function encrypt(payload, p256dh, auth) {
  const uaPublic = unb64u(p256dh), authSecret = unb64u(auth);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(te.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, te.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plain = concat(te.encode(payload), new Uint8Array([2])); // 0x02 = last (only) record
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, plain));
  const rs = new Uint8Array([0, 0, 16, 0]); // record size 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

export class WebPushError extends Error {
  constructor(statusCode, body) { super(`Push service answered ${statusCode}`); this.statusCode = statusCode; this.body = body; }
}

// sub: { endpoint, keys: { p256dh, auth } }, vapid: { publicKey, privateKey, subject }
export async function sendNotification(sub, payload, vapid, { TTL = 3600, urgency = "normal", topic } = {}) {
  const body = await encrypt(payload, sub.keys.p256dh, sub.keys.auth);
  const headers = { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: String(TTL), Urgency: urgency,
    Authorization: await vapidAuth(sub.endpoint, vapid) };
  if (topic) headers.Topic = topic;
  const r = await fetch(sub.endpoint, { method: "POST", headers, body });
  if (r.status >= 200 && r.status < 300) return { statusCode: r.status };
  throw new WebPushError(r.status, await r.text().catch(() => ""));
}
