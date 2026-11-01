# NAWEC Alerts


Power outage alerts by free phone push notifications, email (Brevo) and SMS, sent by location. Hospitals and other critical sites are alerted first and must confirm.

## What it does

- **Public page:** shows current and upcoming outages, with a filter by area.
- **Sign up (no password):** people choose their type (hospital, clinic, home, and so on) and their places, then confirm their email with a 6-digit code. Alerts only start after the email is confirmed, so nobody can sign up someone else's inbox. A welcome email confirms their alerts are on.
- **Sign in (no password):** enter your email and we send a code. People stay signed in on that device.
- **Alerts for everywhere:** people can tick "Alert me about every outage, everywhere". They get an email for every outage in any area. SMS, the hospital "I received this" button and reminders still only apply to their own places, and a hospital outside the affected area never blocks a short-notice planned cut.
- **Phone alerts (web push, free):** the main alert. People tap **Turn on phone alerts** on their dashboard or in Your details.
  - Android: works in Chrome, installed or not.
  - iPhone/iPad (iOS 16.4+): only after **Share → Add to Home Screen**, then opening the app from the Home Screen. The dashboard shows these steps on iPhone.
  - Same rules as email: their own places, plus every outage if they ticked "everywhere".
  - **Email is the backup.** If a phone shows the alert, no email is sent. If a person has no phone set up, or the push fails, the email goes at once. If the phone doesn't confirm it showed the alert within 5 minutes (`PUSH_GRACE_MINUTES`), the email is sent then.
  - Hospitals and critical sites always get email and SMS too, as before. Anyone can tick "Email me every alert too".
  - Signing out removes that phone, so the next person doesn't get the alerts.
- **Unsubscribe:** every alert email has a one-click unsubscribe link. People can turn alerts back on from that page, from their dashboard, or by saving their details.
- **Staff and admins** sign in with a password ("Staff sign in" on the sign-in page). To set it the first time, use "Set or reset password".
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
netlify/functions/reminders.mjs  runs every 5 min (reminders, retries, backup emails)
netlify/lib/core.mjs          database, auth, web push, Brevo email, SMS, sending
netlify/lib/places.mjs       every place, by region
nawec-logo.png                official NAWEC logo (add this file yourself)
manifest.json, icon.svg
sw.js                         offline cache + shows push alerts
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
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | Optional. Push keys are made automatically and kept in the database. Only set these to use your own (`npx web-push generate-vapid-keys`). |
| `PUSH_GRACE_MINUTES` | Optional, default `5`. How long email waits for the phone. |

4. Deploy, then sign up with your admin email and confirm the code. Then go to Sign in → Staff sign in → "Set or reset password" to set your admin password.
5. To make someone staff: go to Staff portal → Subscribers and change their role. They then set their password the same way.

## NAWEC logo

Put the official logo in the project root as `nawec-logo.png` (a square PNG works best). It shows in the staff portal automatically.

## Notes

- **Brevo limit:** the free plan sends 300 emails a day. Phone alerts are free and unlimited, and people whose phone shows the alert don't use an email, so the more people turn on phone alerts, the further the free plan goes.
- **SMS:** critical sites always get SMS. Other people get it only if they turned it on. httpSMS sends from one phone, so it is fine for hospitals but slow for thousands of people. Use Brevo SMS or another bulk provider for big areas.
- **Retries:** if sending runs out of time or fails, the reminders function retries every 5 minutes. Staff can also press **Retry unsent**.
