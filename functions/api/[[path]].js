// Cloudflare Pages entry for /api/* : same code as netlify/functions/api.mjs
import { bridge, runCron } from "../../cloudflare/adapter.js";

export async function onRequest({ request, env }) {
  bridge(env);
  if (new URL(request.url).pathname === "/api/cron")
    return runCron(request, env, async () => (await import("../../netlify/functions/reminders.mjs")).default()); // every 5 minutes
  const { default: handler } = await import("../../netlify/functions/api.mjs");
  return handler(request);
}
