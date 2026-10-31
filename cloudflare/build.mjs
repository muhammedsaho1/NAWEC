// Copies the website files into dist/ for Cloudflare Pages (so source code isn't published).
import { mkdirSync, cpSync, readdirSync } from "node:fs";
mkdirSync("dist", { recursive: true });
for (const f of readdirSync(".")) if (/\.(html|js|json|png|svg|ico|webmanifest|txt)$/.test(f) && !/^(package|package-lock)\.json$/.test(f)) cpSync(f, `dist/${f}`);
for (const f of ["_headers"]) try { cpSync(f, `dist/${f}`); } catch {}
console.log("dist ready:", readdirSync("dist").join(", "));
