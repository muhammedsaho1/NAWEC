// Runs every 10 minutes:
//  - reminds critical sites ~1 hour before a planned cut
//  - marks planned cuts as active once they start
//  - retries alerts that are still pending/failed
import { q, ensureSchema, dispatch } from '../lib/core.mjs';

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

  const retry = await q(`SELECT DISTINCT d.outage_id, d.stage FROM deliveries d JOIN outages o ON o.id=d.outage_id
    WHERE (d.email_status IN ('pending','failed') OR d.sms_status IN ('pending','failed'))
      AND o.created_at > now() - interval '2 days' LIMIT 10`);
  for (const r of retry) {
    if (Date.now() > deadline) break;
    await dispatch(r.outage_id, r.stage, { criticalOnly: r.stage === 'reminder', deadline });
  }
  return new Response('ok');
};

export const config = { schedule: '*/10 * * * *' };
