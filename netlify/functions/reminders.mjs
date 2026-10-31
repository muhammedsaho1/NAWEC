// Runs every 5 minutes:
//  - reminds critical sites ~1 hour before a planned cut
//  - marks planned cuts as active once they start
//  - retries alerts that are still pending/failed
//  - sends the backup email when a phone didn't show the push
import { q, ensureSchema, dispatch, PUSH_GRACE_MIN } from '../lib/core.mjs';

export default async () => {
  await ensureSchema();
  const deadline = Date.now() + 20000;

  const due = await q(`SELECT id FROM outages
    WHERE status='scheduled' AND kind='planned' AND NOT reminder_sent
      AND starts_at BETWEEN now() AND now() + interval '70 minutes'`);
  for (const o of due) {
    await q(`UPDATE outages SET reminder_sent=true WHERE id=$1`, [o.id]);
    await dispatch(o.id, 'reminder', { criticalOnly: true, deadline });
  }

  await q(`UPDATE outages SET status='active' WHERE status='scheduled' AND starts_at <= now()`);

  // Phones that showed the push don't need the backup email.
  await q(`UPDATE deliveries SET email_status='not_needed' WHERE email_status='held' AND push_seen_at IS NOT NULL`);

  // Retry unsent alerts, and send backup emails where the phone never showed the push.
  const retry = await q(`SELECT DISTINCT d.outage_id, d.stage FROM deliveries d JOIN outages o ON o.id=d.outage_id
    WHERE (d.email_status IN ('pending','failed') OR d.sms_status IN ('pending','failed') OR d.push_status = 'pending'
       OR (d.email_status='held' AND d.push_sent_at < now() - make_interval(mins => $1::int)))
      AND o.created_at > now() - interval '2 days' LIMIT 10`, [PUSH_GRACE_MIN]);
  for (const r of retry) {
    if (Date.now() > deadline) break;
    await dispatch(r.outage_id, r.stage, { criticalOnly: r.stage === 'reminder', deadline });
  }
  return new Response('ok');
};

export const config = { schedule: '*/5 * * * *' };
