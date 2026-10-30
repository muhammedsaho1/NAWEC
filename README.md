# NAWEC Alerts

Power outage alerts by email (Brevo) and SMS, sent by location. Hospitals and other critical sites are alerted first and must confirm.

## What it does

- **Public page:** shows current and upcoming outages, with a filter by area.
- **Sign up:** people choose their type (hospital, clinic, home, and so on) and their places, and they're in straight away with no code. They stay signed in on that device, and a welcome email confirms their alerts are on. Only admin emails confirm with a code.
- **Places:** 271 towns, villages and neighbourhoods across all 7 regions (`netlify/lib/places.mjs`). If a place is missing, anyone can add it, and staff can remove wrong ones in Staff portal → Places.
- **Staff portal:** staff post a planned cut or an emergency, choose the areas, see who will be alerted, and send.
- **Hospital protection:**
  - Critical sites get email and SMS, and are sent to first.
  - A planned cut that gives less than `MIN_NOTICE_HOURS` notice to a critical site is blocked unless staff write a reason. The reason is logged.
  - Critical sites get a reminder about 1 hour before the cut.
  - Each critical site taps **"I received this"**. Staff see who hasn't confirmed, with a tap-to-call number.
- **Restore and cancel:** these send a follow-up to everyone who was alerted.

## Files

```
index.html                    whole frontend (public, subscriber, staff)
netlify/functions/api.mjs     API at /api/*
netlify/functions/reminders.mjs  runs every 10 min (reminders, retries)
netlify/lib/core.mjs          database, auth, Brevo email, SMS, sending
netlify/lib/places.mjs       every place, by region
nawec-logo.png                official NAWEC logo (add this file yourself)
manifest.json, sw.js, icon.svg
```

The database tables are created automatically on the first request, and the areas are pre-filled. Staff can add more areas in the portal.

## Setup

1. Push to GitHub, then import the repo in Netlify. Check the team name at the top left first.
2. Add Neon: Netlify → Extensions → Neon, or set `DATABASE_URL`.
3. In Netlify → Site configuration → Environment variables, add these:

| Variable | Example |
|---|---|
| `BREVO_API_KEY` | `xkeysib-...` |
| `BREVO_SENDER_EMAIL` | `alerts@yourdomain.com`. The sender must be verified in Brevo. |
| `BREVO_SENDER_NAME` | `NAWEC Alerts` |
| `ADMIN_EMAILS` | `m92292363@gmail.com`. This email becomes admin on sign-up. |
| `SMS_PROVIDER` | `httpsms` or `brevo`. Leave it empty to send email only. |
| `HTTPSMS_API_KEY` / `HTTPSMS_FROM` | Needed if you use httpSMS. |
| `BREVO_SMS_SENDER` | Needed if you use Brevo SMS. Up to 11 characters, for example `NAWEC`. |
| `MIN_NOTICE_HOURS` | `2` |
| `SITE_URL` | `https://nawec-alerts.netlify.app` |

4. Deploy, then sign up with your admin email. You land in the staff portal.
5. To make someone staff: go to Staff portal → Subscribers and change their role.

## NAWEC logo

Put the official logo in the project root as `nawec-logo.png` (a square PNG works best). It shows in the staff portal automatically.

## Notes

- **Brevo limit:** the free plan sends 300 emails a day. Each person counts as one email, so a large area needs a paid Brevo plan.
- **SMS:** critical sites always get SMS. Other people get it only if they turned it on. httpSMS sends from one phone, so it is fine for hospitals but slow for thousands of people. Use Brevo SMS or another bulk provider for big areas.
- **Retries:** if sending runs out of time or fails, the reminders function retries every 10 minutes. Staff can also press **Retry unsent**.
