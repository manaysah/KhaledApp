# Our Little Tide (KhaledApp)

Private family memory space on **Cloudflare Workers** (`khaledapp`) with static assets in `public/`, email allowlist, and TOTP (authenticator) second factor.

## Layout (Workers Builds)

```
public/          # static HTML/CSS/assets (assets.directory)
src/worker.js    # auth gate + /api/*
migrations/      # D1 schema
wrangler.toml    # name=khaledapp, [assets], empty [previews], D1, KV
```

Workers Builds PR checks run `wrangler preview` and require both `[assets]` and an empty `[previews]` block.

## Auth flow

1. Visitor opens the site → redirected to `/login` unless a full session exists.
2. **Email allowlist** — only emails in D1 `allowlist` may request a login code. Site admin `mhmd.manaysah@gmail.com` is always seeded (bare `@gmail` normalizes to `@gmail.com`).
3. **Email OTP** — 6-digit code emailed via [Resend](https://resend.com) (or shown in the UI when `AUTH_DEV_MODE=true`).
4. **TOTP** — after email verification, enroll or verify an authenticator app. Secrets are AES-GCM encrypted at rest.
5. Full session cookie (`olt_sid`) is issued only after TOTP succeeds. The Worker gates `/` and `/admin.html` until then.
6. **Admin** (`/admin.html`) lists allowlisted emails and can add/revoke (admin row cannot be removed).

## Bindings & secrets (do not commit secret values)

| Binding / secret | Type | Purpose |
| --- | --- | --- |
| `ASSETS` | Assets (`./public`) | Static site |
| `DB` | D1 (`khaledapp-auth`) | Allowlist + user TOTP metadata |
| `AUTH_KV` | KV | OTP codes, sessions, rate limits |
| `SESSION_SECRET` | Secret | Fallback crypto material |
| `TOTP_ENCRYPTION_KEY` | Secret | Encrypt TOTP secrets at rest |
| `RESEND_API_KEY` | Secret | Send login codes |
| `EMAIL_FROM` | Var or secret | Verified Resend from-address |
| `AUTH_DEV_MODE` | Var | `true` only for local/preview testing |

```bash
npm install
npm run db:migrate:remote

npx wrangler secret put SESSION_SECRET
npx wrangler secret put TOTP_ENCRYPTION_KEY
npx wrangler secret put RESEND_API_KEY
# Set EMAIL_FROM in dashboard vars (or wrangler.toml [vars] after verifying the domain)
```

### Local

```bash
cp .dev.vars.example .dev.vars   # AUTH_DEV_MODE=true
npm run db:migrate:local
npm run dev
```

## Deploy

```bash
npm run deploy:dry   # validate Worker + assets upload
npm run deploy
```

## Logo

Site logo/favicon live under `public/assets/` (merged from main). Auth pages reuse the same mark.
