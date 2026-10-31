// Runs the existing Netlify function code on Cloudflare Pages, unchanged.
// - copies Cloudflare's environment variables into process.env (what the code already reads)
// - passes the visitor's IP
// - /api/cron?key=CRON_SECRET runs the scheduled job (called by the sds-cron Worker)
import { neonConfig } from "@neondatabase/serverless";

export function bridge(env = {}) {
  globalThis.process ??= { env: {} };
  process.env ??= {};
  for (const [k, v] of Object.entries(env)) if (typeof v === "string") process.env[k] = v;
  if (env.NEON_FETCH_ENDPOINT) neonConfig.fetchEndpoint = () => env.NEON_FETCH_ENDPOINT; // local testing only
}

export const ipOf = (req) => req.headers.get("cf-connecting-ip") || "0.0.0.0";

export async function runCron(req, env, job) {
  const url = new URL(req.url);
  const key = url.searchParams.get("key") || req.headers.get("x-cron-key") || "";
  if (!env.CRON_SECRET || key !== env.CRON_SECRET) return new Response("Not found", { status: 404 });
  const out = await job();
  return out instanceof Response ? out : Response.json(out ?? { ok: true });
}
