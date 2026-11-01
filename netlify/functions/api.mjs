// Single API router for NAWEC Alerts — served at /api/*
import {
  q, ensureSchema, hashPassword, checkPassword, createSession, userFromRequest, sha256, randomCode, randomToken,
  sendCodeEmail, sendWelcomeEmail, publicUser, adminEmails, CRITICAL_KINDS, ALL_KINDS, normPhone, dispatch,
  outageWithAreas, audit, inArea, vapidKeys, pushToUser,
} from '../lib/core.mjs';

const MIN_NOTICE_HOURS = Number(process.env.MIN_NOTICE_HOURS || 2);

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const fail = (status, msg) => { throw new HttpError(status, msg); };

const cleanEmail = (e) => String(e || '').trim().toLowerCase();
const isEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const str = (s, max = 200) => String(s ?? '').trim().slice(0, max);
const isStaffRole = (r) => r === 'staff' || r === 'admin';
const ids = (arr) => [...new Set((Array.isArray(arr) ? arr : []).map(Number).filter((n) => Number.isInteger(n) && n > 0))];

async function issueCode(email, purpose) {
  const [prev] = await q(`SELECT created_at FROM codes WHERE email=$1 AND purpose=$2`, [email, purpose]);
  if (prev && Date.now() - new Date(prev.created_at).getTime() < 60_000) fail(429, 'Please wait a minute before asking for another code.');
  const code = randomCode();
  await q(`INSERT INTO codes (email, purpose, code_hash, expires_at, created_at, attempts)
           VALUES ($1,$2,$3, now() + interval '15 minutes', now(), 0)
           ON CONFLICT (email, purpose) DO UPDATE SET code_hash=EXCLUDED.code_hash, expires_at=EXCLUDED.expires_at, created_at=now(), attempts=0`,
    [email, purpose, sha256(code)]);
  const r = await sendCodeEmail(email, code, purpose);
  if (!r.ok) { console.error(r.error); fail(502, 'Could not send the email. Try again shortly.'); }
}

async function useCode(email, purpose, code) {
  const [row] = await q(`SELECT * FROM codes WHERE email=$1 AND purpose=$2`, [email, purpose]);
  if (!row || new Date(row.expires_at) < new Date()) fail(400, 'Code expired. Ask for a new one.');
  if (row.attempts >= 5) fail(429, 'Too many tries. Ask for a new code.');
  if (row.code_hash !== sha256(str(code, 10))) {
    await q(`UPDATE codes SET attempts = attempts + 1 WHERE email=$1 AND purpose=$2`, [email, purpose]);
    fail(400, 'Wrong code.');
  }
  await q(`DELETE FROM codes WHERE email=$1 AND purpose=$2`, [email, purpose]);
}

async function setUserAreas(userId, areaIds) {
  await q(`DELETE FROM user_areas WHERE user_id=$1`, [userId]);
  if (areaIds.length) {
    await q(`INSERT INTO user_areas (user_id, area_id) SELECT $1, a.id FROM areas a WHERE a.id = ANY($2::int[]) ON CONFLICT DO NOTHING`, [userId, areaIds]);
  }
}

async function meWithAreas(u) {
  const areas = await q(`SELECT a.id, a.name, a.region FROM user_areas ua JOIN areas a ON a.id=ua.area_id WHERE ua.user_id=$1 ORDER BY a.region, a.name`, [u.id]);
  const [{ n }] = await q(`SELECT count(*)::int AS n FROM push_subs WHERE user_id=$1`, [u.id]);
  return { ...publicUser(u), areas, push_devices: n };
}

/* ---------------- Routes ---------------- */
const routes = [];
const route = (method, pattern, handler, auth = null) => {
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$');
  routes.push({ method, re, handler, auth });
};

/* Public */
route('GET', '/areas', async () => json(await q(`SELECT id, name, region, added_by_user FROM areas ORDER BY region, name`)));

const REGION_NAMES = ['Banjul', 'Kanifing', 'West Coast', 'North Bank', 'Lower River', 'Central River', 'Upper River'];
const tidyName = (s) => str(s, 60).replace(/\s+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

// Anyone can add a place that's missing from the list (it's then available to everyone).
route('POST', '/areas', async ({ body }) => {
  const name = tidyName(body.name);
  const region = REGION_NAMES.includes(body.region) ? body.region : null;
  if (name.length < 2 || !/[a-z]/i.test(name)) fail(400, 'Enter the name of your place.');
  if (!region) fail(400, 'Choose the region.');
  const [same] = await q(`SELECT id, name, region, added_by_user FROM areas WHERE lower(name)=lower($1) AND region=$2`, [name, region]);
  if (same) return json(same);
  const [{ n }] = await q(`SELECT count(*)::int AS n FROM areas WHERE added_by_user AND created_at > now() - interval '1 hour'`);
  if (n > 200) fail(429, 'Too many new places right now. Pick the nearest place for now.');
  const [a] = await q(`INSERT INTO areas (name, region, added_by_user) VALUES ($1,$2,true) RETURNING id, name, region, added_by_user`, [name, region]);
  return json(a);
});

route('GET', '/public/outages', async () => {
  const rows = await q(`
    SELECT o.id, o.kind, o.status, o.title, o.message, o.starts_at, o.ends_at, o.restored_at,
      COALESCE(json_agg(json_build_object('id', a.id, 'name', a.name, 'region', a.region) ORDER BY a.region, a.name)
        FILTER (WHERE a.id IS NOT NULL), '[]') AS areas
    FROM outages o LEFT JOIN outage_areas oa ON oa.outage_id=o.id LEFT JOIN areas a ON a.id=oa.area_id
    WHERE (o.status IN ('scheduled','active') AND o.starts_at < now() + interval '14 days')
       OR (o.status = 'restored' AND o.restored_at > now() - interval '24 hours')
    GROUP BY o.id ORDER BY CASE o.status WHEN 'active' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END, o.starts_at
    LIMIT 100`);
  return json(rows);
});

route('POST', '/ack', async ({ body }) => {
  const token = str(body.token, 100);
  if (!token) fail(400, 'Missing token');
  const [d] = await q(`UPDATE deliveries SET acked_at = COALESCE(acked_at, now()) WHERE ack_token=$1
                       RETURNING id, outage_id, user_id, acked_at`, [token]);
  if (!d) fail(404, 'This confirmation link is not valid.');
  const o = await outageWithAreas(d.outage_id);
  const [u] = await q(`SELECT org_name, name FROM users WHERE id=$1`, [d.user_id]);
  return json({ ok: true, acked_at: d.acked_at, facility: u?.org_name || u?.name, outage: o && { title: o.title, kind: o.kind, starts_at: o.starts_at, ends_at: o.ends_at, areas: o.areas } });
});

// One-click unsubscribe from the link at the bottom of every alert email.
route('POST', '/unsubscribe', async ({ body }) => {
  const token = str(body.token, 100);
  const [u] = token ? await q(`UPDATE users SET subscribed=false WHERE unsub_token=$1 RETURNING id, email`, [token]) : [];
  if (!u) fail(404, 'This unsubscribe link is not valid.');
  await q(`UPDATE deliveries SET email_status = CASE WHEN email_status IN ('pending','failed') THEN 'skipped' ELSE email_status END,
                                 sms_status   = CASE WHEN sms_status   IN ('pending','failed') THEN 'skipped' ELSE sms_status END,
                                 push_status  = CASE WHEN push_status = 'pending' THEN 'skipped' ELSE push_status END
           WHERE user_id=$1`, [u.id]);
  await q(`UPDATE deliveries SET email_status='skipped' WHERE user_id=$1 AND email_status='held'`, [u.id]);
  await audit(u.id, 'unsubscribed', {});
  return json({ ok: true, email: u.email });
});
route('POST', '/resubscribe', async ({ body }) => {
  const token = str(body.token, 100);
  const [u] = token ? await q(`UPDATE users SET subscribed=true WHERE unsub_token=$1 RETURNING id, email`, [token]) : [];
  if (!u) fail(404, 'This link is not valid.');
  await audit(u.id, 'resubscribed', {});
  return json({ ok: true, email: u.email });
});

/* Web push */
route('GET', '/push/key', async () => json({ key: (await vapidKeys()).publicKey }));

// The phone calls this when it shows an alert, so the backup email isn't sent.
route('POST', '/push/seen', async ({ body }) => {
  const token = str(body.r, 100);
  if (token) await q(`UPDATE deliveries SET push_seen_at = COALESCE(push_seen_at, now()),
                        email_status = CASE WHEN email_status='held' THEN 'not_needed' ELSE email_status END
                      WHERE ack_token=$1`, [token]);
  return json({ ok: true });
});

// One-tap join: no email, no code. The phone's push subscription is the account.
route('POST', '/device/join', async ({ body, req }) => {
  const sub = body.subscription || {};
  const endpoint = str(sub.endpoint, 1000), p256dh = str(sub.keys?.p256dh, 200), auth = str(sub.keys?.auth, 100);
  if (!/^https:\/\//.test(endpoint) || !p256dh || !auth) fail(400, 'Allow alerts on this phone first.');
  const kind = body.kind === 'hospital' ? 'hospital' : 'household';
  const critical = kind === 'hospital';
  const areaIds = ids(body.area_ids);
  if (!areaIds.length) fail(400, 'Pick your area.');
  if (critical && !str(body.org_name)) fail(400, 'Enter the hospital name.');
  // same phone joining again: reuse its account
  const [old] = await q(`SELECT u.* FROM push_subs p JOIN users u ON u.id=p.user_id WHERE p.endpoint=$1 AND u.push_only`, [endpoint]);
  let userId = old?.id;
  if (!userId) {
    const [u] = await q(`INSERT INTO users (email, name, org_name, phone, kind, critical, sms_opt_in, email_verified, push_only, unsub_token)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,true,true,$8) RETURNING id`,
      [`phone-${randomToken(12)}@device.invalid`, str(body.org_name, 120), str(body.org_name, 160), normPhone(body.phone), kind, critical, critical, randomToken(24)]);
    userId = u.id;
  } else {
    await q(`UPDATE users SET subscribed=true, kind=$2, critical=$3, org_name=COALESCE(NULLIF($4,''),org_name), phone=COALESCE(NULLIF($5,''),phone) WHERE id=$1`,
      [userId, kind, critical, str(body.org_name, 160), normPhone(body.phone)]);
  }
  await setUserAreas(userId, areaIds);
  await q(`INSERT INTO push_subs (user_id, endpoint, p256dh, auth, device) VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (endpoint) DO UPDATE SET user_id=EXCLUDED.user_id, p256dh=EXCLUDED.p256dh, auth=EXCLUDED.auth, fails=0`,
    [userId, endpoint, p256dh, auth, str(body.device || req.headers.get('user-agent'), 200)]);
  await audit(userId, 'device_join', { kind });
  const [u] = await q(`SELECT * FROM users WHERE id=$1`, [userId]);
  return json({ token: await createSession(userId), user: await meWithAreas(u) });
});

route('POST', '/push/subscribe', async ({ user, body, req }) => {
  const sub = body.subscription || {};
  const endpoint = str(sub.endpoint, 1000), p256dh = str(sub.keys?.p256dh, 200), auth = str(sub.keys?.auth, 100);
  if (!/^https:\/\//.test(endpoint) || !p256dh || !auth) fail(400, 'This phone could not turn on alerts.');
  // One device belongs to whoever is signed in on it now.
  await q(`INSERT INTO push_subs (user_id, endpoint, p256dh, auth, device) VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (endpoint) DO UPDATE SET user_id=EXCLUDED.user_id, p256dh=EXCLUDED.p256dh, auth=EXCLUDED.auth, device=EXCLUDED.device, fails=0`,
    [user.id, endpoint, p256dh, auth, str(body.device || req.headers.get('user-agent'), 200)]);
  const [{ n }] = await q(`SELECT count(*)::int AS n FROM push_subs WHERE user_id=$1`, [user.id]);
  return json({ ok: true, push_devices: n });
}, 'user');

// Not signed in on purpose: used when signing out, so the next person doesn't get these alerts.
route('POST', '/push/unsubscribe', async ({ body }) => {
  const endpoint = str(body.endpoint, 1000);
  if (endpoint) await q(`DELETE FROM push_subs WHERE endpoint=$1`, [endpoint]);
  return json({ ok: true });
});

route('POST', '/push/test', async ({ user }) => {
  const r = await pushToUser(user.id, { title: 'Phone alerts are on', body: "This is how NAWEC outage alerts will look on this phone.", tag: 'test', url: '/#dashboard' });
  if (!r.devices) fail(400, 'Phone alerts are not on for this account yet.');
  if (!r.sent) fail(502, 'Could not reach your phone. Turn phone alerts off and on again.');
  return json({ ok: true, sent: r.sent });
}, 'user');

/* Auth — subscribers have no password: confirm email once, sign in later with an emailed code.
   Staff and admins also have a password. */
route('POST', '/auth/register', async ({ body }) => {
  const email = cleanEmail(body.email);
  const kind = ALL_KINDS.includes(body.kind) ? body.kind : 'household';
  const areaIds = ids(body.area_ids);
  const alertAll = body.alert_all === true;
  if (!isEmail(email)) fail(400, 'Enter a valid email.');
  // Name is optional for homes (simple sign-up); critical facilities still give a contact name.
  if (CRITICAL_KINDS.includes(kind) && !str(body.org_name)) fail(400, 'Enter the facility name.');
  if (CRITICAL_KINDS.includes(kind) && !normPhone(body.phone)) fail(400, 'A phone number is required for critical facilities.');
  if (!areaIds.length && !alertAll) fail(400, 'Choose at least one area, or turn on alerts for everywhere.');

  const [existing] = await q(`SELECT id, email_verified FROM users WHERE email=$1`, [email]);
  if (existing?.email_verified) fail(409, 'This email is already signed up. Sign in instead.');
  const fields = [str(body.name, 120), normPhone(body.phone), str(body.org_name, 160), kind, CRITICAL_KINDS.includes(kind), body.sms_opt_in !== false, alertAll];
  let userId;
  if (existing) {
    // not confirmed yet: whoever confirms the email owns these details
    await q(`UPDATE users SET name=$2, phone=$3, org_name=$4, kind=$5, critical=$6, sms_opt_in=$7, alert_all=$8 WHERE id=$1`, [existing.id, ...fields]);
    userId = existing.id;
  } else {
    const [u] = await q(`INSERT INTO users (email, name, phone, org_name, kind, critical, sms_opt_in, alert_all, unsub_token)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, [email, ...fields, randomToken(24)]);
    userId = u.id;
  }
  await setUserAreas(userId, areaIds);
  // Alerts only start once the email is confirmed, so nobody can sign up someone else's inbox.
  await issueCode(email, 'verify');
  return json({ ok: true, need_verify: true, email });
});

route('POST', '/auth/verify', async ({ body }) => {
  const email = cleanEmail(body.email);
  await useCode(email, 'verify', body.code);
  const [u] = await q(`UPDATE users SET email_verified=true, subscribed=true,
                         role = CASE WHEN $2 THEN 'admin' ELSE role END
                       WHERE email=$1 RETURNING *`, [email, adminEmails().includes(email)]);
  if (!u) fail(404, 'Account not found.');
  await audit(u.id, 'verified_email', {});
  const me = await meWithAreas(u);
  try { await sendWelcomeEmail(u, me.areas.map((a) => a.name)); } catch (e) { console.error('welcome email', e); }
  return json({ token: await createSession(u.id), user: me });
});

route('POST', '/auth/resend', async ({ body }) => {
  const email = cleanEmail(body.email);
  const [u] = await q(`SELECT id FROM users WHERE email=$1 AND NOT email_verified`, [email]);
  if (u) await issueCode(email, 'verify');
  return json({ ok: true });
});

// Step 1 of sign-in: email a code. Staff/admin are told to use their password.
route('POST', '/auth/code', async ({ body }) => {
  const email = cleanEmail(body.email);
  if (!isEmail(email)) fail(400, 'Enter a valid email.');
  const [u] = await q(`SELECT id, role, active FROM users WHERE email=$1`, [email]);
  if (u && isStaffRole(u.role)) return json({ use_password: true });
  if (u && u.active) await issueCode(email, 'login');
  return json({ ok: true }); // same answer whether or not the email is signed up
});

// Step 2: code -> signed in. Using the code also confirms the email.
route('POST', '/auth/code-login', async ({ body }) => {
  const email = cleanEmail(body.email);
  await useCode(email, 'login', body.code);
  const [u] = await q(`UPDATE users SET email_verified=true WHERE email=$1 AND active RETURNING *`, [email]);
  if (!u) fail(404, 'Account not found.');
  if (isStaffRole(u.role)) fail(403, 'Staff sign in with a password.');
  return json({ token: await createSession(u.id), user: await meWithAreas(u) });
});

// Staff and admin sign-in.
route('POST', '/auth/login', async ({ body }) => {
  const email = cleanEmail(body.email);
  const [u] = await q(`SELECT * FROM users WHERE email=$1`, [email]);
  if (!u || !checkPassword(String(body.password || ''), u.password_hash)) fail(401, 'Wrong email or password.');
  if (!u.active) fail(403, 'This account is disabled.');
  if (!u.email_verified) {
    await issueCode(email, 'verify').catch(() => {});
    return json({ need_verify: true, email });
  }
  if (adminEmails().includes(email) && u.role !== 'admin') { await q(`UPDATE users SET role='admin' WHERE id=$1`, [u.id]); u.role = 'admin'; }
  return json({ token: await createSession(u.id), user: await meWithAreas(u) });
});

route('POST', '/auth/forgot', async ({ body }) => {
  const email = cleanEmail(body.email);
  const [u] = await q(`SELECT id, role FROM users WHERE email=$1 AND email_verified`, [email]);
  if (u && (isStaffRole(u.role) || adminEmails().includes(email))) await issueCode(email, 'reset');
  return json({ ok: true }); // same answer either way
});

route('POST', '/auth/reset', async ({ body }) => {
  const email = cleanEmail(body.email);
  if (String(body.password || '').length < 8) fail(400, 'Password must be at least 8 characters.');
  await useCode(email, 'reset', body.code);
  const [u] = await q(`UPDATE users SET password_hash=$2, email_verified=true WHERE email=$1 RETURNING *`, [email, hashPassword(body.password)]);
  if (!u) fail(404, 'Account not found.');
  await q(`DELETE FROM sessions WHERE user_id=$1`, [u.id]);
  return json({ token: await createSession(u.id), user: await meWithAreas(u) });
});

route('POST', '/auth/logout', async ({ req }) => {
  const h = req.headers.get('authorization') || '';
  if (h.startsWith('Bearer ')) await q(`DELETE FROM sessions WHERE token_hash=$1`, [sha256(h.slice(7))]);
  return json({ ok: true });
});

/* Subscriber */
route('GET', '/me', async ({ user }) => json(await meWithAreas(user)), 'user');

route('PUT', '/me', async ({ user, body }) => {
  const areaIds = ids(body.area_ids);
  const alertAll = body.alert_all === true;
  if (!areaIds.length && !alertAll) fail(400, 'Choose at least one area, or turn on alerts for everywhere.');
  const kind = ALL_KINDS.includes(body.kind) ? body.kind : user.kind;
  const critical = CRITICAL_KINDS.includes(kind);
  if (critical && !normPhone(body.phone)) fail(400, 'A phone number is required for critical facilities.');
  const kindChanged = kind !== user.kind;
  const [u] = await q(`UPDATE users SET name=$2, phone=$3, org_name=$4, kind=$5, critical=$6, sms_opt_in=$7, subscribed=true, alert_all=$9, email_too=$10,
                         critical_verified = CASE WHEN $8 THEN false ELSE critical_verified END
                       WHERE id=$1 RETURNING *`,
    [user.id, str(body.name, 120) || user.name, normPhone(body.phone), str(body.org_name, 160), kind, critical, body.sms_opt_in !== false, kindChanged, alertAll, body.email_too === true]);
  await setUserAreas(user.id, areaIds);
  return json(await meWithAreas(u));
}, 'user');

route('POST', '/me/subscribed', async ({ user, body }) => {
  const [u] = await q(`UPDATE users SET subscribed=$2 WHERE id=$1 RETURNING *`, [user.id, body.on !== false]);
  await audit(user.id, body.on !== false ? 'resubscribed' : 'unsubscribed', {});
  return json(await meWithAreas(u));
}, 'user');

route('GET', '/me/alerts', async ({ user }) => {
  const rows = await q(`
    SELECT d.id, d.stage, d.sent_at, d.acked_at, d.email_status, d.sms_status, d.push_status, ${inArea('u')} AS in_area,
           o.id AS outage_id, o.kind, o.status, o.title, o.message, o.starts_at, o.ends_at
    FROM deliveries d JOIN outages o ON o.id=d.outage_id JOIN users u ON u.id=d.user_id
    WHERE d.user_id=$1 ORDER BY COALESCE(d.sent_at, o.created_at) DESC LIMIT 100`, [user.id]);
  return json(rows);
}, 'user');

route('POST', '/me/ack/:id', async ({ user, params }) => {
  const [d] = await q(`UPDATE deliveries SET acked_at = COALESCE(acked_at, now()) WHERE id=$1 AND user_id=$2 RETURNING acked_at`, [Number(params.id), user.id]);
  if (!d) fail(404, 'Not found');
  return json({ ok: true, acked_at: d.acked_at });
}, 'user');

/* Staff */
route('GET', '/staff/stats', async () => {
  const [s] = await q(`SELECT
    (SELECT count(*) FROM users WHERE email_verified AND subscribed)::int AS subscribers,
    (SELECT count(*) FROM users WHERE email_verified AND subscribed AND alert_all)::int AS everywhere,
    (SELECT count(DISTINCT p.user_id) FROM push_subs p JOIN users u ON u.id=p.user_id WHERE u.email_verified AND u.subscribed)::int AS on_push,
    (SELECT count(*) FROM users WHERE email_verified AND subscribed AND critical)::int AS critical_sites,
    (SELECT count(*) FROM users WHERE email_verified AND subscribed AND critical AND NOT critical_verified)::int AS critical_unverified,
    (SELECT count(*) FROM outages WHERE status='active')::int AS active_outages,
    (SELECT count(*) FROM outages WHERE status='scheduled')::int AS scheduled_outages,
    (SELECT count(*) FROM deliveries d JOIN users u ON u.id=d.user_id JOIN outages o ON o.id=d.outage_id
       WHERE u.critical AND ${inArea()} AND d.acked_at IS NULL AND d.stage IN ('notice','reminder') AND o.status IN ('scheduled','active'))::int AS unconfirmed_critical,
    (SELECT count(*) FROM deliveries WHERE sent_at > now() - interval '7 days')::int AS alerts_7d`);
  return json(s);
}, 'staff');

route('GET', '/staff/outages', async () => {
  const rows = await q(`
    SELECT o.*, u.name AS created_by_name,
      (SELECT string_agg(a.name, ', ' ORDER BY a.name) FROM outage_areas oa JOIN areas a ON a.id=oa.area_id WHERE oa.outage_id=o.id) AS area_names,
      (SELECT count(DISTINCT d.user_id) FROM deliveries d WHERE d.outage_id=o.id)::int AS recipients,
      (SELECT count(DISTINCT d.user_id) FROM deliveries d JOIN users cu ON cu.id=d.user_id WHERE d.outage_id=o.id AND cu.critical AND ${inArea('cu')})::int AS critical_total,
      (SELECT count(DISTINCT d.user_id) FROM deliveries d JOIN users cu ON cu.id=d.user_id WHERE d.outage_id=o.id AND cu.critical AND ${inArea('cu')} AND d.acked_at IS NOT NULL)::int AS critical_acked
    FROM outages o LEFT JOIN users u ON u.id=o.created_by
    ORDER BY o.created_at DESC LIMIT 200`);
  return json(rows);
}, 'staff');

route('GET', '/staff/outages/:id', async ({ params }) => {
  const o = await outageWithAreas(Number(params.id));
  if (!o) fail(404, 'Not found');
  const stages = await q(`SELECT stage, count(*)::int AS total,
      count(*) FILTER (WHERE email_status='sent')::int AS email_sent,
      count(*) FILTER (WHERE email_status='failed')::int AS email_failed,
      count(*) FILTER (WHERE email_status='pending')::int AS email_pending,
      count(*) FILTER (WHERE email_status='held')::int AS email_held,
      count(*) FILTER (WHERE email_status='not_needed')::int AS email_saved,
      count(*) FILTER (WHERE push_status='sent')::int AS push_sent,
      count(*) FILTER (WHERE push_seen_at IS NOT NULL)::int AS push_seen,
      count(*) FILTER (WHERE sms_status='sent')::int AS sms_sent,
      count(*) FILTER (WHERE sms_status='failed')::int AS sms_failed,
      count(*) FILTER (WHERE sms_status='pending')::int AS sms_pending,
      count(*) FILTER (WHERE acked_at IS NOT NULL)::int AS acked
    FROM deliveries WHERE outage_id=$1 GROUP BY stage`, [o.id]);
  // one row per critical facility: did they confirm any notice/reminder for this outage?
  const critical = await q(`
    SELECT u.id, u.org_name, u.name, u.phone, u.email, u.kind, u.critical_verified,
      max(d.acked_at) AS acked_at,
      bool_or(d.email_status='sent') AS email_ok, bool_or(d.sms_status='sent') AS sms_ok, bool_or(d.push_status='sent') AS push_ok
    FROM deliveries d JOIN users u ON u.id=d.user_id
    WHERE d.outage_id=$1 AND u.critical AND ${inArea()} AND d.stage IN ('notice','reminder')
    GROUP BY u.id ORDER BY max(d.acked_at) IS NOT NULL, u.org_name`, [o.id]);
  return json({ outage: o, stages, critical });
}, 'staff');

route('POST', '/staff/preview', async ({ body }) => {
  const areaIds = ids(body.area_ids);
  if (!areaIds.length) return json({ total: 0, critical: [] });
  const [{ total, everywhere }] = await q(`SELECT count(*)::int AS total, count(*) FILTER (WHERE NOT in_area)::int AS everywhere FROM (
                               SELECT EXISTS (SELECT 1 FROM user_areas ua WHERE ua.user_id=u.id AND ua.area_id = ANY($1::int[])) AS in_area, u.alert_all
                               FROM users u WHERE u.active AND u.email_verified AND u.subscribed) t
                               WHERE in_area OR alert_all`, [areaIds]);
  const critical = await q(`SELECT DISTINCT u.id, u.org_name, u.name, u.kind, u.phone, u.critical_verified
                            FROM users u JOIN user_areas ua ON ua.user_id=u.id
                            WHERE ua.area_id = ANY($1::int[]) AND u.active AND u.email_verified AND u.subscribed AND u.critical
                            ORDER BY u.org_name`, [areaIds]);
  return json({ total, everywhere, critical, min_notice_hours: MIN_NOTICE_HOURS });
}, 'staff');

route('POST', '/staff/outages', async ({ user, body }) => {
  const kind = body.kind === 'emergency' ? 'emergency' : 'planned';
  const title = str(body.title, 160);
  const message = str(body.message, 2000);
  const areaIds = ids(body.area_ids);
  const startsAt = body.starts_at ? new Date(body.starts_at) : new Date();
  const endsAt = body.ends_at ? new Date(body.ends_at) : null;
  if (!title) fail(400, 'Enter a title.');
  if (!areaIds.length) fail(400, 'Choose at least one area.');
  if (isNaN(startsAt)) fail(400, 'Invalid start time.');
  if (endsAt && (isNaN(endsAt) || endsAt <= startsAt)) fail(400, 'End time must be after the start time.');

  // Hospital protection: a planned cut must give critical sites enough notice.
  let overrideReason = null;
  if (kind === 'planned') {
    const hoursAhead = (startsAt - Date.now()) / 3_600_000;
    const [{ n }] = await q(`SELECT count(DISTINCT u.id)::int AS n FROM users u JOIN user_areas ua ON ua.user_id=u.id
                             WHERE ua.area_id = ANY($1::int[]) AND u.critical AND u.email_verified AND u.active AND u.subscribed`, [areaIds]);
    if (n > 0 && hoursAhead < MIN_NOTICE_HOURS) {
      overrideReason = str(body.override_reason, 500);
      if (overrideReason.length < 10) {
        fail(422, `This planned cut affects ${n} hospital/critical site(s) but gives less than ${MIN_NOTICE_HOURS} hours' notice. Move the start time later, or give a reason to override.`);
      }
    }
  }
  const status = kind === 'emergency' || startsAt <= new Date() ? 'active' : 'scheduled';
  const [o] = await q(`INSERT INTO outages (kind, status, title, message, starts_at, ends_at, override_reason, created_by)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [kind, status, title, message, startsAt.toISOString(), endsAt?.toISOString() || null, overrideReason, user.id]);
  await q(`INSERT INTO outage_areas (outage_id, area_id) SELECT $1, a.id FROM areas a WHERE a.id = ANY($2::int[])`, [o.id, areaIds]);
  // if it starts within the reminder window, no separate reminder is needed
  if (kind === 'emergency' || startsAt - Date.now() < 75 * 60_000) await q(`UPDATE outages SET reminder_sent=true WHERE id=$1`, [o.id]);
  await audit(user.id, 'outage_created', { id: o.id, kind, overrideReason });
  const result = await dispatch(o.id, 'notice');
  return json({ id: o.id, result });
}, 'staff');

route('POST', '/staff/outages/:id/restore', async ({ user, params, body }) => {
  const id = Number(params.id);
  const [o] = await q(`UPDATE outages SET status='restored', restored_at=now(),
                         message = CASE WHEN $2 <> '' THEN $2 ELSE message END
                       WHERE id=$1 AND status IN ('active','scheduled') RETURNING id`, [id, str(body.message, 2000)]);
  if (!o) fail(400, 'This outage is not active.');
  await audit(user.id, 'outage_restored', { id });
  return json({ result: await dispatch(id, 'restored') });
}, 'staff');

route('POST', '/staff/outages/:id/cancel', async ({ user, params }) => {
  const id = Number(params.id);
  const [o] = await q(`UPDATE outages SET status='cancelled' WHERE id=$1 AND status='scheduled' RETURNING id`, [id]);
  if (!o) fail(400, 'Only scheduled outages can be cancelled.');
  await audit(user.id, 'outage_cancelled', { id });
  return json({ result: await dispatch(id, 'cancelled') });
}, 'staff');

route('POST', '/staff/outages/:id/resend', async ({ params, body }) => {
  const id = Number(params.id);
  const stage = ['notice', 'reminder', 'restored', 'cancelled'].includes(body.stage) ? body.stage : 'notice';
  return json({ result: await dispatch(id, stage) });
}, 'staff');

route('GET', '/staff/subscribers', async ({ url }) => {
  const term = str(url.searchParams.get('q'), 100);
  const filter = url.searchParams.get('filter') || '';
  const rows = await q(`
    SELECT u.id, u.email, u.name, u.phone, u.org_name, u.kind, u.role, u.critical, u.critical_verified,
      u.email_verified, u.active, u.subscribed, u.alert_all, u.sms_opt_in, u.created_at,
      (SELECT string_agg(a.name, ', ' ORDER BY a.name) FROM user_areas ua JOIN areas a ON a.id=ua.area_id WHERE ua.user_id=u.id) AS area_names
    FROM users u
    WHERE ($1 = '' OR u.email ILIKE '%'||$1||'%' OR u.name ILIKE '%'||$1||'%' OR u.org_name ILIKE '%'||$1||'%' OR u.phone ILIKE '%'||$1||'%')
      AND ($2 <> 'critical' OR u.critical)
      AND ($2 <> 'unverified' OR (u.critical AND NOT u.critical_verified))
      AND ($2 <> 'staff' OR u.role IN ('staff','admin'))
    ORDER BY u.critical DESC, u.created_at DESC LIMIT 300`, [term, filter]);
  return json(rows);
}, 'staff');

route('POST', '/staff/subscribers/:id/verify-critical', async ({ user, params, body }) => {
  const val = body.verified !== false;
  await q(`UPDATE users SET critical_verified=$2 WHERE id=$1`, [Number(params.id), val]);
  await audit(user.id, 'critical_verified', { id: Number(params.id), val });
  return json({ ok: true });
}, 'staff');

route('POST', '/staff/areas', async ({ user, body }) => {
  const name = str(body.name, 80), region = str(body.region, 80);
  if (!name || !region) fail(400, 'Enter the area name and region.');
  const [a] = await q(`INSERT INTO areas (name, region) VALUES ($1,$2) ON CONFLICT (name, region) DO UPDATE SET name=EXCLUDED.name RETURNING *`, [name, region]);
  await audit(user.id, 'area_added', a);
  return json(a);
}, 'staff');

route('DELETE', '/staff/areas/:id', async ({ user, params }) => {
  const [a] = await q(`DELETE FROM areas WHERE id=$1 AND added_by_user RETURNING name, region`, [Number(params.id)]);
  if (!a) fail(400, 'Only places added by users can be removed.');
  await audit(user.id, 'area_removed', a);
  return json({ ok: true });
}, 'staff');

/* Admin */
route('POST', '/admin/users/:id', async ({ user, params, body }) => {
  const id = Number(params.id);
  if (id === user.id) fail(400, "You can't change your own account here.");
  if (body.role && ['subscriber', 'staff', 'admin'].includes(body.role)) await q(`UPDATE users SET role=$2 WHERE id=$1`, [id, body.role]);
  if (typeof body.active === 'boolean') {
    await q(`UPDATE users SET active=$2 WHERE id=$1`, [id, body.active]);
    if (!body.active) await q(`DELETE FROM sessions WHERE user_id=$1`, [id]);
  }
  await audit(user.id, 'user_changed', { id, ...body });
  return json({ ok: true });
}, 'admin');

/* ---------------- Entry ---------------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, '').replace(/^\/\.netlify\/functions\/api/, '') || '/';
  try {
    await ensureSchema();
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = path.match(r.re);
      if (!m) continue;
      let user = null;
      if (r.auth) {
        user = await userFromRequest(req);
        if (!user) fail(401, 'Please sign in.');
        if (r.auth === 'staff' && !['staff', 'admin'].includes(user.role)) fail(403, 'Staff only.');
        if (r.auth === 'admin' && user.role !== 'admin') fail(403, 'Admins only.');
      }
      let body = {};
      if (req.method !== 'GET') { try { body = await req.json(); } catch { body = {}; } }
      return await r.handler({ req, url, body, user, params: m.groups || {} });
    }
    return json({ error: 'Not found' }, 404);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: 'Something went wrong. Please try again.' }, 500);
  }
};

export const config = { path: '/api/*' };
