// Shared helpers: database, auth, email (Brevo), SMS, dispatch.
import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';
import { generateVAPIDKeys, sendNotification } from './webpush.mjs';
import { PLACES, PLACE_COUNT } from './places.mjs';

/* ---------------- Database ---------------- */
let _sql;
export function db() {
  if (!_sql) {
    const url = process.env.DATABASE_URL || process.env.NETLIFY_DATABASE_URL;
    if (!url) throw new Error('DATABASE_URL is not set');
    _sql = neon(url);
  }
  return _sql;
}
// q('select ... where id = $1', [id]) -> rows
export async function q(text, params = []) {
  // Works with every version of the Neon driver (older ones use sql(text, params)).
  const sql = db();
  return typeof sql.query === 'function' ? sql.query(text, params) : sql(text, params);
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    org_name TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'household',
    role TEXT NOT NULL DEFAULT 'subscriber',
    critical BOOLEAN NOT NULL DEFAULT false,
    critical_verified BOOLEAN NOT NULL DEFAULT false,
    sms_opt_in BOOLEAN NOT NULL DEFAULT true,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS areas (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    region TEXT NOT NULL,
    UNIQUE (name, region)
  )`,
  `CREATE TABLE IF NOT EXISTS user_areas (
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    area_id INT NOT NULL REFERENCES areas(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, area_id)
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS codes (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (email, purpose)
  )`,
  `CREATE TABLE IF NOT EXISTS outages (
    id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    title TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ,
    override_reason TEXT,
    reminder_sent BOOLEAN NOT NULL DEFAULT false,
    created_by INT REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    restored_at TIMESTAMPTZ
  )`,
  `CREATE TABLE IF NOT EXISTS outage_areas (
    outage_id INT NOT NULL REFERENCES outages(id) ON DELETE CASCADE,
    area_id INT NOT NULL REFERENCES areas(id) ON DELETE CASCADE,
    PRIMARY KEY (outage_id, area_id)
  )`,
  `CREATE TABLE IF NOT EXISTS deliveries (
    id SERIAL PRIMARY KEY,
    outage_id INT NOT NULL REFERENCES outages(id) ON DELETE CASCADE,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    ack_token TEXT UNIQUE NOT NULL,
    email_status TEXT NOT NULL DEFAULT 'pending',
    sms_status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    sent_at TIMESTAMPTZ,
    acked_at TIMESTAMPTZ,
    UNIQUE (outage_id, user_id, stage)
  )`,
  `CREATE INDEX IF NOT EXISTS deliveries_outage_idx ON deliveries(outage_id, stage)`,
  `CREATE INDEX IF NOT EXISTS user_areas_area_idx ON user_areas(area_id)`,
  `CREATE TABLE IF NOT EXISTS audit (
    id SERIAL PRIMARY KEY,
    user_id INT,
    action TEXT NOT NULL,
    detail JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
];

let schemaReady = false;
export async function ensureSchema() {
  if (schemaReady) return;
  for (const st of SCHEMA) await q(st);
  await q(`ALTER TABLE areas ADD COLUMN IF NOT EXISTS added_by_user BOOLEAN NOT NULL DEFAULT false`);
  await q(`ALTER TABLE areas ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()`);
  // No passwords for subscribers: they confirm their email and sign in with an emailed code.
  await q(`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscribed BOOLEAN NOT NULL DEFAULT true`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS unsub_token TEXT UNIQUE`);
  // "Alert me everywhere": email for every outage, not just the user's own places.
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS alert_all BOOLEAN NOT NULL DEFAULT false`);
  // Web push: free alerts to phones (Android + iPhone installed app). Email becomes the backup.
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_too BOOLEAN NOT NULL DEFAULT false`);
  await q(`CREATE TABLE IF NOT EXISTS push_subs (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT UNIQUE NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    device TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ok_at TIMESTAMPTZ,
    fails INT NOT NULL DEFAULT 0
  )`);
  await q(`CREATE INDEX IF NOT EXISTS push_subs_user_idx ON push_subs(user_id)`);
  await q(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  // Alerts sent before push existed get 'old' so they are never pushed late; new ones start 'pending'.
  await q(`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS push_status TEXT NOT NULL DEFAULT 'old'`);
  await q(`ALTER TABLE deliveries ALTER COLUMN push_status SET DEFAULT 'pending'`);
  await q(`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS push_sent_at TIMESTAMPTZ`);
  await q(`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS push_seen_at TIMESTAMPTZ`);
  await q(`UPDATE users SET unsub_token = replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '') WHERE unsub_token IS NULL`);
  // Load every place in one query; new places in places.mjs are picked up automatically.
  const [{ n }] = await q('SELECT count(*)::int AS n FROM areas WHERE NOT added_by_user');
  if (n < PLACE_COUNT) {
    const names = [], regions = [];
    for (const [region, list] of Object.entries(PLACES)) for (const name of list) { names.push(name); regions.push(region); }
    await q(`INSERT INTO areas (name, region) SELECT * FROM unnest($1::text[], $2::text[]) ON CONFLICT (name, region) DO NOTHING`, [names, regions]);
  }
  schemaReady = true;
}

/* ---------------- Crypto / auth ---------------- */
export const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const randomCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');

export function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
export function checkPassword(pw, stored) {
  const [alg, salt, hash] = String(stored || '').split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 64);
  const real = Buffer.from(hash, 'hex');
  return real.length === test.length && crypto.timingSafeEqual(real, test);
}

export async function createSession(userId) {
  const token = randomToken();
  await q(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '10 years')`, [sha256(token), userId]);
  return token;
}

export async function userFromRequest(req) {
  const h = req.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  const rows = await q(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active`,
    [sha256(token)]
  );
  return rows[0] || null;
}

export function adminEmails() {
  return (process.env.ADMIN_EMAILS || '').split(',').map((e) => e.trim().toLowerCase()).filter(Boolean);
}

export const CRITICAL_KINDS = ['hospital', 'clinic', 'health_centre', 'dialysis', 'care_home', 'water_pumping'];
export const ALL_KINDS = [...CRITICAL_KINDS, 'pharmacy', 'school', 'business', 'household', 'other'];

export function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, email: u.email, name: u.name, phone: u.phone, org_name: u.org_name, kind: u.kind,
    role: u.role, critical: u.critical, critical_verified: u.critical_verified,
    sms_opt_in: u.sms_opt_in, email_verified: u.email_verified, subscribed: u.subscribed !== false, alert_all: !!u.alert_all,
    email_too: !!u.email_too, created_at: u.created_at,
  };
}

/* ---------------- Text helpers ---------------- */
export function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
    .replace(/\{/g, '&#123;').replace(/\}/g, '&#125;'); // keep Brevo's {{ }} template engine away from user text
}
export function normPhone(p) {
  let s = String(p || '').replace(/[^\d+]/g, '');
  if (!s) return '';
  if (s.startsWith('00')) s = '+' + s.slice(2);
  if (/^\d{7}$/.test(s)) s = '+220' + s; // local Gambian 7-digit number
  if (/^220\d{7}$/.test(s)) s = '+' + s;
  return s;
}
const TZ = process.env.APP_TIMEZONE || 'Africa/Banjul';
export function fmtTime(d) {
  if (!d) return '';
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: TZ, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
  }).format(new Date(d));
}
export function siteUrl() {
  return (process.env.SITE_URL || process.env.URL || 'http://localhost:8888').replace(/\/$/, '');
}

/* ---------------- Email (Brevo) ---------------- */
const BRAND = () => process.env.BREVO_SENDER_NAME || 'NAWEC Alerts';

const host = () => siteUrl().replace(/^https?:\/\//, '');
// Footer for alert emails; unsubUrl may be a Brevo placeholder like {{params.unsub_url}}.
export const alertFooter = (unsubUrl) => `You get this because you subscribed to outage alerts for your area.
  <a href="${siteUrl()}/#login" style="color:#2B59FF">Change your areas</a> &middot; <a href="${unsubUrl}" style="color:#6b7690">Unsubscribe</a>`;
const codeFooter = () => `You got this because this email was entered at <a href="${siteUrl()}" style="color:#2B59FF">${host()}</a>.`;

export function emailShell({ heading, accent = '#2B59FF', bodyHtml, footer }) {
  return `<!doctype html><html><body style="margin:0;background:#f2f4f8;font-family:Arial,Helvetica,sans-serif;color:#13203a">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f8;padding:24px 12px">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:22px;overflow:hidden;border:1px solid #e3e7ef">
<tr><td style="background:${accent};padding:18px 24px;color:#ffffff">
  <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.85">${esc(BRAND())}</div>
  <div style="font-size:21px;font-weight:bold;margin-top:4px">${heading}</div>
</td></tr>
<tr><td style="padding:22px 24px;font-size:15px;line-height:1.55">${bodyHtml}</td></tr>
<tr><td style="padding:14px 24px;border-top:1px solid #eef1f6;font-size:12px;color:#6b7690">
  ${footer || alertFooter(siteUrl())}
</td></tr>
</table></td></tr></table></body></html>`;
}

// messages: [{ to: {email, name}, params: {...} }] — shared subject/html with {{params.x}} placeholders.
export async function sendBrevoBatch({ subject, html, messages }) {
  const key = process.env.BREVO_API_KEY;
  if (!key) return { ok: false, error: 'BREVO_API_KEY not set' };
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': key, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      sender: { email: process.env.BREVO_SENDER_EMAIL, name: BRAND() },
      subject,
      htmlContent: html,
      messageVersions: messages.map((m) => ({ to: [m.to], params: m.params || {} })),
    }),
  });
  if (!res.ok) return { ok: false, error: `Brevo ${res.status}: ${(await res.text()).slice(0, 300)}` };
  return { ok: true };
}

export async function sendCodeEmail(email, code, purpose) {
  const what = { reset: 'set your staff password', login: 'sign in' }[purpose] || 'confirm your email and turn on your alerts';
  const html = emailShell({
    heading: 'Your code', footer: codeFooter(),
    bodyHtml: `<p>Use this code to ${what}:</p>
<div style="font-size:34px;font-weight:bold;letter-spacing:8px;background:#f2f4f8;border-radius:10px;padding:16px;text-align:center">${code}</div>
<p style="color:#6b7690;font-size:13px">It expires in 15 minutes. If you didn't ask for it, ignore this email.</p>`,
  });
  return sendBrevoBatch({ subject: `${code} is your ${BRAND()} code`, html, messages: [{ to: { email } }] });
}

export async function sendWelcomeEmail(user, areaNames) {
  const crit = user.critical;
  const html = emailShell({
    heading: 'Alerts are on', footer: alertFooter(`${siteUrl()}/?unsub=${user.unsub_token}`),
    bodyHtml: `<p>Hello ${esc(user.name || 'there')},</p>
${areaNames.length ? `<p>You'll now get power outage alerts for:</p>
<p style="font-weight:bold">${esc(areaNames.join(', '))}</p>` : ''}
${user.alert_all ? `<p>${areaNames.length ? 'You also chose' : 'You chose'} <b>alerts for everywhere</b>, so we'll email you about every outage${areaNames.length ? '. SMS and urgent alerts are only for your own places' : ''}.</p>` : ''}
${crit ? `<p style="background:#fff5f5;border-left:4px solid #E0213F;padding:10px 14px;border-radius:6px">${esc(user.org_name || 'Your facility')} is registered as a <b>critical facility</b>. You'll be alerted first, by email and SMS, and asked to confirm each warning.</p>` : ''}
<p><a href="${siteUrl()}" style="display:inline-block;background:#2B59FF;color:#fff;text-decoration:none;font-weight:bold;padding:12px 20px;border-radius:10px">Open NAWEC Alerts</a></p>`,
  });
  return sendBrevoBatch({ subject: 'Your power outage alerts are on', html, messages: [{ to: { email: user.email, name: user.org_name || user.name } }] });
}

/* ---------------- SMS ---------------- */
export async function sendSms(to, content) {
  const provider = (process.env.SMS_PROVIDER || '').toLowerCase();
  if (!provider || !to) return { ok: false, skipped: true };
  try {
    if (provider === 'httpsms') {
      const res = await fetch('https://api.httpsms.com/v1/messages/send', {
        method: 'POST',
        headers: { 'x-api-key': process.env.HTTPSMS_API_KEY, 'content-type': 'application/json' },
        body: JSON.stringify({ content, from: process.env.HTTPSMS_FROM, to }),
      });
      return res.ok ? { ok: true } : { ok: false, error: `httpSMS ${res.status}` };
    }
    if (provider === 'brevo') {
      const res = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', {
        method: 'POST',
        headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json' },
        body: JSON.stringify({
          sender: (process.env.BREVO_SMS_SENDER || 'NAWEC').slice(0, 11),
          recipient: to.replace(/^\+/, ''),
          content, type: 'transactional',
        }),
      });
      return res.ok ? { ok: true } : { ok: false, error: `Brevo SMS ${res.status}` };
    }
    return { ok: false, error: `Unknown SMS_PROVIDER ${provider}` };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

/* ---------------- Web push ---------------- */
// VAPID keys: taken from env if set, otherwise made once and kept in the database (no setup needed).
let _vapid;
export async function vapidKeys() {
  if (_vapid) return _vapid;
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    _vapid = { publicKey: process.env.VAPID_PUBLIC_KEY, privateKey: process.env.VAPID_PRIVATE_KEY };
  } else {
    const k = await generateVAPIDKeys();
    await q(`INSERT INTO settings (key, value) VALUES ('vapid', $1) ON CONFLICT (key) DO NOTHING`, [JSON.stringify(k)]);
    const [row] = await q(`SELECT value FROM settings WHERE key='vapid'`);
    _vapid = JSON.parse(row.value);
  }
  // Apple needs a real mailto: or https: contact here.
  _vapid.subject = process.env.VAPID_SUBJECT || `mailto:${adminEmails()[0] || process.env.BREVO_SENDER_EMAIL || 'alerts@nawec.gm'}`;
  return _vapid;
}

// Sends one notification to every device of a user. Returns { sent, failed, devices }.
export async function pushToUser(userId, payload, { urgent = false } = {}) {
  const vapid = await vapidKeys();
  const subs = await q(`SELECT id, endpoint, p256dh, auth FROM push_subs WHERE user_id=$1`, [userId]);
  let sent = 0, failed = 0;
  const body = JSON.stringify(payload);
  await Promise.all(subs.map(async (s) => {
    try {
      await sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, body, vapid,
        { TTL: 6 * 3600, urgency: urgent ? 'high' : 'normal', topic: payload.tag ? String(payload.tag).replace(/[^\w-]/g, '').slice(0, 32) : undefined });
      sent++;
      await q(`UPDATE push_subs SET last_ok_at=now(), fails=0 WHERE id=$1`, [s.id]);
    } catch (e) {
      failed++;
      // 404/410: the phone removed the app or turned notifications off — forget this device.
      if (e.statusCode === 404 || e.statusCode === 410 || e.statusCode === 403) await q(`DELETE FROM push_subs WHERE id=$1`, [s.id]);
      else await q(`UPDATE push_subs SET fails=fails+1 WHERE id=$1`, [s.id]);
      console.error('push', e.statusCode, String(e.body || e.message).slice(0, 200));
    }
  }));
  return { sent, failed, devices: subs.length };
}

// How long email waits for the phone to confirm it showed the push before sending the backup email.
export const PUSH_GRACE_MIN = Number(process.env.PUSH_GRACE_MINUTES || 5);

/* ---------------- Outage dispatch ---------------- */
// SQL: is user `u` in one of the areas of the outage on delivery `d`?
// Hospital rules (confirm button, forced SMS, reminders) only apply in the user's own places.
export const inArea = (u = 'u', d = 'd') =>
  `EXISTS (SELECT 1 FROM user_areas iua JOIN outage_areas ioa ON ioa.area_id = iua.area_id WHERE iua.user_id = ${u}.id AND ioa.outage_id = ${d}.outage_id)`;

export async function outageWithAreas(id) {
  const [o] = await q('SELECT * FROM outages WHERE id = $1', [id]);
  if (!o) return null;
  o.areas = await q(
    `SELECT a.id, a.name, a.region FROM outage_areas oa JOIN areas a ON a.id = oa.area_id
     WHERE oa.outage_id = $1 ORDER BY a.region, a.name`, [id]);
  return o;
}

function areaLabel(areas, max = 4) {
  const names = areas.map((a) => a.name);
  return names.length <= max ? names.join(', ') : `${names.slice(0, max).join(', ')} +${names.length - max} more`;
}

function stageContent(o, stage) {
  const areas = areaLabel(o.areas);
  const when = o.ends_at ? `${fmtTime(o.starts_at)} – ${fmtTime(o.ends_at)}` : `From ${fmtTime(o.starts_at)}`;
  if (stage === 'restored') {
    return {
      accent: '#079A69', heading: 'Power restored',
      subject: `Power restored: ${areas}`,
      sms: `NAWEC: Power has been restored in ${areas}. ${o.title}`,
      lead: `Power supply has been restored in your area.`,
    };
  }
  if (stage === 'cancelled') {
    return {
      accent: '#5B6478', heading: 'Planned outage cancelled',
      subject: `Cancelled: planned power cut in ${areas}`,
      sms: `NAWEC: The planned power cut for ${areas} (${fmtTime(o.starts_at)}) is CANCELLED.`,
      lead: `The planned power cut below will no longer go ahead.`,
    };
  }
  if (stage === 'reminder') {
    return {
      accent: '#E5700A', heading: 'Power cut starts soon',
      subject: `Reminder: power cut in ${areas} starts ${fmtTime(o.starts_at)}`,
      sms: `NAWEC REMINDER: Power cut in ${areas} starts ${fmtTime(o.starts_at)}. Prepare backup power now.`,
      lead: `This is a reminder that the planned power cut below starts within the hour.`,
    };
  }
  if (o.kind === 'emergency') {
    return {
      accent: '#E0213F', heading: 'Emergency power outage',
      subject: `Power outage alert: ${areas}`,
      sms: `NAWEC ALERT: Emergency power outage in ${areas}. ${when}. ${o.title}`,
      lead: `An unplanned power outage is affecting your area.`,
    };
  }
  return {
    accent: '#2B59FF', heading: 'Planned power cut',
    subject: `Planned power cut: ${areas} — ${fmtTime(o.starts_at)}`,
    sms: `NAWEC: Planned power cut in ${areas}. ${when}. ${o.title}`,
    lead: `A planned power cut will affect your area.`,
  };
}

function buildEmailHtml(o, c) {
  const rows = [
    ['What', esc(o.title)],
    ['When', o.ends_at ? `${esc(fmtTime(o.starts_at))} – ${esc(fmtTime(o.ends_at))}` : `From ${esc(fmtTime(o.starts_at))}`],
    ['Areas', esc(o.areas.map((a) => a.name).join(', '))],
  ].map(([k, v]) => `<tr><td style="padding:6px 12px 6px 0;color:#6b7690;vertical-align:top;white-space:nowrap">${k}</td><td style="padding:6px 0;font-weight:bold">${v}</td></tr>`).join('');
  const msg = o.message ? `<p style="background:#f6f8fb;border-left:4px solid ${c.accent};padding:10px 14px;border-radius:6px;white-space:pre-line">${esc(o.message)}</p>` : '';
  // {{params.*}} are filled per recipient by Brevo.
  return emailShell({
    heading: c.heading, accent: c.accent, footer: alertFooter('{{params.unsub_url}}'),
    bodyHtml: `<p>Hello {{params.name}},</p><p>${c.lead}</p>{{params.why}}
<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:15px;margin:8px 0 14px">${rows}</table>
${msg}
{{params.critical_block}}
<p style="margin-top:18px"><a href="{{params.view_url}}" style="color:#2B59FF">View all outages</a></p>`,
  });
}

function criticalBlock(ackUrl, stage) {
  if (stage === 'restored' || stage === 'cancelled') return '';
  return `<div style="border:2px solid #E0213F;border-radius:10px;padding:14px 16px;margin:14px 0;background:#fff5f5">
<div style="font-weight:bold;color:#E0213F;margin-bottom:6px">Critical facility — please confirm</div>
<div style="font-size:14px;margin-bottom:12px">Tap below so NAWEC knows your team has this warning. Please plan surgeries and life-support around this time and check your backup power.</div>
<a href="${ackUrl}" style="display:inline-block;background:#E0213F;color:#ffffff;text-decoration:none;font-weight:bold;padding:12px 20px;border-radius:8px">I received this</a></div>`;
}

/**
 * Sends one stage of an outage to everyone subscribed to its areas.
 * Critical facilities are sent first. Safe to call again: only unsent items are retried.
 */
export async function dispatch(outageId, stage, { criticalOnly = false, deadline = Date.now() + 20000 } = {}) {
  const o = await outageWithAreas(outageId);
  if (!o) throw new Error('Outage not found');
  const areaIds = o.areas.map((a) => a.id);
  if (!areaIds.length) return { recipients: 0 };

  // 1. create delivery rows for everyone in the affected areas
  const recips = await q(
    `SELECT u.id FROM users u
     WHERE u.active AND u.email_verified AND u.subscribed AND (
       EXISTS (SELECT 1 FROM user_areas ua WHERE ua.user_id = u.id AND ua.area_id = ANY($1::int[]))
       ${criticalOnly ? 'AND u.critical' : 'OR u.alert_all'})`,
    [areaIds]);
  if (recips.length) {
    await q(`INSERT INTO deliveries (outage_id, user_id, stage, ack_token)
             SELECT $1, t.uid, $2, t.tok FROM unnest($3::int[], $4::text[]) AS t(uid, tok)
             ON CONFLICT (outage_id, user_id, stage) DO NOTHING`,
      [outageId, stage, recips.map((r) => r.id), recips.map(() => randomToken(24))]);
  }

  const c = stageContent(o, stage);
  const html = buildEmailHtml(o, c);
  const base = siteUrl();

  // 2. web push first (free, instant). Same people as email: own places + "everywhere".
  const pendingPush = await q(
    `SELECT d.id, d.user_id, d.ack_token, u.critical, u.email_too, ${inArea()} AS in_area
     FROM deliveries d JOIN users u ON u.id = d.user_id
     WHERE d.outage_id = $1 AND d.stage = $2 AND d.push_status = 'pending' AND u.subscribed
     ORDER BY (u.critical AND ${inArea()}) DESC, d.id`, [outageId, stage]);
  let pushSent = 0, pushFailed = 0;
  const areasShort = areaLabel(o.areas, 3);
  const when = o.ends_at ? `${fmtTime(o.starts_at)} – ${fmtTime(o.ends_at)}` : `From ${fmtTime(o.starts_at)}`;
  for (let i = 0; i < pendingPush.length; i += 20) {
    if (Date.now() > deadline) break;
    await Promise.all(pendingPush.slice(i, i + 20).map(async (d) => {
      const crit = d.critical && d.in_area && stage !== 'restored' && stage !== 'cancelled';
      const r = await pushToUser(d.user_id, {
        title: c.heading + ' · ' + areasShort,
        body: (stage === 'restored' || stage === 'cancelled' ? o.title : `${when}. ${o.title}`) + (crit ? ' — Tap to confirm you received this.' : '') + (d.in_area ? '' : ' (Outside your places)'),
        tag: `o${o.id}-${stage}`,
        url: '/#dashboard',
        r: d.ack_token, // lets the phone report "shown", so the backup email isn't needed
        urgent: crit || o.kind === 'emergency',
      }, { urgent: crit || o.kind === 'emergency' || stage === 'reminder' });
      // 'none' = no phone set up; email covers it straight away.
      const st = r.sent ? 'sent' : r.devices ? 'failed' : 'none';
      if (r.sent) pushSent++; else if (r.devices) pushFailed++;
      await q(`UPDATE deliveries SET push_status=$2, push_sent_at = CASE WHEN $2='sent' THEN COALESCE(push_sent_at, now()) ELSE push_sent_at END,
                 sent_at = CASE WHEN $2='sent' THEN COALESCE(sent_at, now()) ELSE sent_at END WHERE id=$1`, [d.id, st]);
      // Email is the backup: hold it if the push went out, unless this is a hospital/critical site or the user wants both.
      if (r.sent && !(d.critical && d.in_area) && !d.email_too) {
        await q(`UPDATE deliveries SET email_status='held' WHERE id=$1 AND email_status='pending'`, [d.id]);
      }
    }));
  }
  // Phone showed the push: no backup email needed.
  await q(`UPDATE deliveries SET email_status='not_needed' WHERE outage_id=$1 AND stage=$2 AND email_status='held' AND push_seen_at IS NOT NULL`, [outageId, stage]);

  // 3. emails (backup), critical facilities first, batched.
  // Held emails go out if the phone hasn't confirmed the push within PUSH_GRACE_MIN minutes.
  const pendingEmail = await q(
    `SELECT d.id, d.ack_token, u.email, u.name, u.org_name, u.critical, u.unsub_token, ${inArea()} AS in_area
     FROM deliveries d JOIN users u ON u.id = d.user_id
     WHERE d.outage_id = $1 AND d.stage = $2 AND u.subscribed AND (d.email_status IN ('pending','failed')
       OR (d.email_status='held' AND d.push_seen_at IS NULL AND d.push_sent_at < now() - make_interval(mins => $3::int)))
     ORDER BY (u.critical AND ${inArea()}) DESC, d.id`, [outageId, stage, PUSH_GRACE_MIN]);
  let emailSent = 0, emailFailed = 0;
  for (let i = 0; i < pendingEmail.length; i += 90) {
    if (Date.now() > deadline) break;
    const chunk = pendingEmail.slice(i, i + 90);
    const r = await sendBrevoBatch({
      subject: c.subject, html,
      messages: chunk.map((d) => ({
        to: { email: d.email, name: d.org_name || d.name || d.email },
        params: {
          name: esc(d.name || d.org_name || 'there'),
          view_url: base,
          why: d.in_area ? '' : '<p style="color:#6b7690;font-size:13px">This is not in your places. You get it because you chose alerts for everywhere.</p>',
          critical_block: d.critical && d.in_area ? criticalBlock(`${base}/?ack=${d.ack_token}`, stage) : '',
          unsub_url: `${base}/?unsub=${d.unsub_token}`,
        },
      })),
    });
    const ids = chunk.map((d) => d.id);
    if (r.ok) {
      emailSent += ids.length;
      await q(`UPDATE deliveries SET email_status='sent', sent_at = COALESCE(sent_at, now()), error=NULL WHERE id = ANY($1::int[])`, [ids]);
    } else {
      emailFailed += ids.length;
      await q(`UPDATE deliveries SET email_status='failed', error=$2 WHERE id = ANY($1::int[])`, [ids, r.error]);
    }
  }

  // 4. SMS: critical facilities always, others if they opted in
  const pendingSms = await q(
    `SELECT d.id, d.ack_token, u.phone, u.critical, u.sms_opt_in, ${inArea()} AS in_area FROM deliveries d JOIN users u ON u.id = d.user_id
     WHERE d.outage_id = $1 AND d.stage = $2 AND d.sms_status IN ('pending','failed') AND u.subscribed
     ORDER BY u.critical DESC, d.id`, [outageId, stage]);
  let smsSent = 0, smsFailed = 0, smsSkipped = 0;
  const smsOn = !!process.env.SMS_PROVIDER;
  const smsWanted = [], skipIds = [];
  for (const d of pendingSms) {
    const phone = normPhone(d.phone);
    // SMS only for the user's own places; "everywhere" alerts go by email only.
    if (!smsOn || !phone || !d.in_area || !(d.critical || d.sms_opt_in)) skipIds.push(d.id);
    else smsWanted.push({ ...d, phone });
  }
  if (skipIds.length) {
    smsSkipped = skipIds.length;
    await q(`UPDATE deliveries SET sms_status='skipped' WHERE id = ANY($1::int[])`, [skipIds]);
  }
  for (let i = 0; i < smsWanted.length; i += 5) {
    if (Date.now() > deadline) break;
    const chunk = smsWanted.slice(i, i + 5);
    await Promise.all(chunk.map(async (d) => {
      const text = d.critical && stage !== 'restored' && stage !== 'cancelled'
        ? `${c.sms} Confirm: ${base}/?ack=${d.ack_token}`
        : c.sms;
      const r = await sendSms(d.phone, text.slice(0, 459));
      if (r.ok) { smsSent++; await q(`UPDATE deliveries SET sms_status='sent', sent_at = COALESCE(sent_at, now()) WHERE id=$1`, [d.id]); }
      else { smsFailed++; await q(`UPDATE deliveries SET sms_status='failed', error=$2 WHERE id=$1`, [d.id, r.error]); }
    }));
  }

  const [{ left }] = await q(
    `SELECT count(*)::int AS left FROM deliveries WHERE outage_id=$1 AND stage=$2 AND (email_status='pending' OR sms_status='pending')`,
    [outageId, stage]);
  return { recipients: recips.length, pushSent, pushFailed, emailSent, emailFailed, smsSent, smsFailed, smsSkipped, stillPending: left };
}

export async function audit(userId, action, detail) {
  try { await q('INSERT INTO audit (user_id, action, detail) VALUES ($1,$2,$3)', [userId, action, JSON.stringify(detail || {})]); } catch {}
}
