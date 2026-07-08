[中文](./README.md) | **English**

# Bitwarden Workers

> A Cloudflare Workers implementation of the Bitwarden Server API, fully compatible with all official Bitwarden clients (Web Vault, Desktop, Browser Extension, Mobile).
>
> Zero servers, zero ops — run your own personal/family password manager on Cloudflare's free tier.
>
> All vault data is end-to-end encrypted by the client before being stored in [Cloudflare D1](https://developers.cloudflare.com/d1/) — the server only holds ciphertext, so even a full database leak cannot reveal your plaintext secrets. D1 itself provides AES-256-GCM encryption at rest and TLS encryption in transit, with keys managed by Cloudflare infrastructure — no extra configuration needed. D1 also creates automatic backups every hour, with point-in-time restore up to 30 days — even if you accidentally wipe all data, you can roll back instantly via the Cloudflare Dashboard or `wrangler d1 time-travel`.

## Features

| Module | Endpoint | Description |
|--------|----------|-------------|
| Identity | `/identity/*` | Registration, login, token issuance, WebAuthn/FIDO2 |
| Accounts | `/api/accounts/*` | User profile, key management, master password |
| Sync | `/api/sync` | Full vault sync |
| Ciphers | `/api/ciphers/*` | Credential CRUD, batch ops, attachments, sharing |
| Folders | `/api/folders/*` | Folder management |
| Organizations | `/api/organizations/*` | Org/member/collection/group/policy management |
| Collections | `/api/collections/*` | Collection management |
| Two-Factor | `/api/two-factor/*` | 2FA setup (TOTP, WebAuthn, etc.) |
| WebAuthn | `/api/webauthn/*` | Passkey registration & authentication |
| Auth Requests | `/api/auth-requests/*` | Passwordless login approval |
| Sends | `/api/sends/*` | Bitwarden Send (encrypted text/file sharing) |
| Devices | `/api/devices/*` | Device management |
| Events | `/api/events/*` | Audit logs |
| Emergency Access | `/api/emergency-access/*` | Emergency access |
| Settings | `/api/settings/*` | Equivalent domains and user settings |
| Reports | `/api/reports/*` | Organization security reports |
| Icons | `/{hostname}/icon.png` | Website icon fetching & caching (shared across users) |
| Notifications | `/notifications/hub` | Real-time push (WebSocket / Durable Objects) |
| Config | `/api/config` | Server configuration |
| Tasks | `/api/tasks/*` | Scheduled task management |
| Org Licenses | `/api/organizations/licenses/*` | Self-hosted organization licenses |
| Attachments | `/attachments/:cipherId/:attachmentId` | Attachment downloads |

## Tech Stack

| Component | Technology |
|-----------|------------|
| Runtime | [Cloudflare Workers](https://workers.cloudflare.com/) |
| Web Framework | [Hono](https://hono.dev/) |
| Database | [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite) |
| ORM | [Drizzle ORM](https://orm.drizzle.team/) |
| Object Storage | [Cloudflare R2](https://developers.cloudflare.com/r2/) (attachments) |
| Cache | [Cloudflare KV](https://developers.cloudflare.com/kv/) (Icons) + Edge Cache |
| Real-time | [Durable Objects](https://developers.cloudflare.com/durable-objects/) (WebSocket) |
| Scheduled Jobs | [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/) |
| Auth | JWT (HMAC-SHA256) |
| Encryption | Web Crypto API / PBKDF2-SHA256 |

---

## Quick Start

### Prerequisites

- Node.js >= 22 (required by Wrangler 4.x)
- npm
- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier is sufficient)

### Local Development

```bash
npm install
npm run db:generate
npm run db:migrate:local
npm run dev
```

The local server runs at `http://localhost:8787` by default.

---

## Deployment

Two options are available: **Manual Deployment** and **Fork + GitHub Actions (automated)**.

### Option 1: Manual Deployment

#### 1. Create Cloudflare Resources

```bash
npx wrangler login

# D1 database
npx wrangler d1 create bitwarden-db

# R2 bucket (attachments)
npx wrangler r2 bucket create bitwarden-attachments

# KV (Icons cache)
npx wrangler kv namespace create ICONS_CACHE
npx wrangler kv namespace create ICONS_CACHE --preview
```

#### 2. Update `wrangler.toml`

Fill in the IDs from the previous step:

```toml
[[d1_databases]]
database_id = "<your-d1-database-id>"

[[kv_namespaces]]
binding = "ICONS_CACHE"
id = "<your-kv-production-id>"
preview_id = "<your-kv-preview-id>"
```

#### 3. Run Migrations & Deploy

```bash
npm run db:migrate:remote
npx wrangler secret put JWT_SECRET    # enter a strong random string
npm run deploy
```

#### 4. Verify

```bash
curl https://<your-worker-domain>/alive
curl -I https://<your-worker-domain>/github.com/icon.png
```

---

### Option 2: Fork + GitHub Actions (Automated)

Recommended for long-term maintenance. Pushing to `main` automatically runs type checks, database migrations, and deployment.

#### 1. Fork & Enable Actions

- Fork this repository on GitHub.
- Go to the **Actions** tab in your fork and enable workflows.

#### 2. Create Cloudflare Resources Locally

```bash
git clone <your-fork-url>
cd workers
npm ci
npx wrangler login

npx wrangler d1 create bitwarden-db
npx wrangler r2 bucket create bitwarden-attachments
npx wrangler kv namespace create ICONS_CACHE
npx wrangler kv namespace create ICONS_CACHE --preview
```

Note down the D1 `database_id`, KV `id`, and `preview_id` from the output.

#### 3. Create a Cloudflare API Token

Go to [Cloudflare Dashboard > API Tokens](https://dash.cloudflare.com/profile/api-tokens), select **Create Custom Token**, and configure the following permissions:

| Scope | Resource | Permission |
|-------|----------|------------|
| Account | D1 | Edit |
| Account | Workers KV Storage | Edit |
| Account | Workers R2 Storage | Edit |
| Account | Workers Scripts | Edit |
| Account | Account Settings | Read |
| User | Memberships | Read |
| User | User Details | Read |

#### 4. Configure GitHub Secrets

In your fork's **Settings > Secrets and variables > Actions**, add:

| Secret Name | Source |
|---|---|
| `CLOUDFLARE_API_TOKEN` | API Token from step 3 |
| `CLOUDFLARE_ACCOUNT_ID` | Account ID from Cloudflare Dashboard sidebar |
| `D1_DATABASE_ID` | D1 database ID from step 2 |
| `ICONS_CACHE_ID` | KV production ID from step 2 |
| `ICONS_CACHE_PREVIEW_ID` | KV preview ID from step 2 |

> The CI workflow automatically replaces local placeholders in `wrangler.toml` with production values from Secrets before deploying.
> If any Secret is missing, the workflow fails immediately and tells you which one.

#### 5. Set Production Secret

```bash
npx wrangler secret put JWT_SECRET
```

> `JWT_SECRET` is sensitive — never commit it to the repository or `wrangler.toml`.

#### 6. Trigger First Deployment

```bash
git commit --allow-empty -m "chore: trigger first deployment"
git push origin main
```

#### 7. Verify

- Confirm `Deploy to Cloudflare Workers` succeeds in GitHub **Actions**.
- Visit `https://<your-worker-domain>/alive` — should return the current timestamp.
- Visit `https://<your-worker-domain>/github.com/icon.png` — should return an icon image.

---

## Configure Bitwarden Clients

In any Bitwarden client's "Self-hosted" settings, enter your Worker URL:

```
Server URL: https://<your-worker-domain>
```

All clients (Web Vault, Desktop, Browser Extension, Mobile) use the same URL.

---

## Environment Variables

Configured in `[vars]` of `wrangler.toml`. Use `npx wrangler secret put` for sensitive values.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | — | **Must change**. JWT signing key — set via `wrangler secret put` |
| `JWT_EXPIRATION` | `3600` | Access token lifetime (seconds) |
| `JWT_REFRESH_EXPIRATION` | `2592000` | Refresh token lifetime (seconds), default 30 days |
| `GLOBAL_PREMIUM` | `true` | Enable Premium features globally |

### Registration & Invitations

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGNUPS_ALLOWED` | `auto` | Registration control — see below |
| `VAULT_BASE_URL` | — | Web Vault URL (e.g. `https://vault.example.com`) for invitation links |
| `FORCE_INVITE_REGISTER` | — | Set `true` to force invitations through registration flow |
| `INSTALLATION_ID` | — | Installation ID for self-hosted license validation |

#### Registration Control (`SIGNUPS_ALLOWED`)

| Value | Behavior |
|-------|----------|
| `auto` | **Default**. Allows registration when no users exist; auto-closes after first signup |
| `true` | Always allow registration |
| `false` | Always block registration (invitations only) |

> Organization invitations always work regardless of this setting.
> Typical usage: keep the default `auto` — the first person registers, then open signup is automatically disabled.

### Icons Cache

The icon service caches by domain — the same website icon is shared across all users, eliminating redundant fetches.

| Variable | Default | Description |
|----------|---------|-------------|
| `ICONS_CACHE_SUCCESS_TTL_SECONDS` | `1209600` | Successful cache TTL (14 days) |
| `ICONS_CACHE_NEGATIVE_TTL_SECONDS` | `43200` | Negative cache TTL (12 hours) — avoids repeated requests for icon-less sites |
| `ICONS_MAX_IMAGE_BYTES` | `51200` | Max cacheable icon size (50KB) |

Cost optimization tips:
- For high traffic, increase success TTL to 30 days (`2592000`).
- Keep negative TTL in the 6–24 hour range to avoid long-term error lock-in.

---

## Cloudflare Resource Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `DB` | D1 | Primary database |
| `ATTACHMENTS` | R2 | Attachment file storage |
| `ICONS_CACHE` | KV | Icons cache (shared across users) |
| `NOTIFICATION_HUB` | Durable Object | Real-time WebSocket push |

---

## Scheduled Jobs

Executed automatically via Cron Triggers — no additional infrastructure required:

| Cron | Job | Description |
|------|-----|-------------|
| `*/5 * * * *` | DeleteSendsJob | Purge expired Sends every 5 minutes |
| `0 0 * * *` | DeleteCiphersJob | Permanently delete soft-deleted ciphers older than 30 days (daily at midnight) |
| `0 22 * * 5` | DatabaseExpiredGrantsJob | Clean up expired refresh tokens (Fridays at 22:00 UTC) |

---

## Project Structure

```
workers/
├── src/
│   ├── index.ts                  # Worker entry point & route mounting
│   ├── routes/                   # API routes
│   │   ├── identity.ts           # Auth & tokens
│   │   ├── accounts.ts           # User accounts
│   │   ├── sync.ts               # Data sync
│   │   ├── ciphers.ts            # Vault items
│   │   ├── folders.ts            # Folders
│   │   ├── organizations.ts      # Organization management
│   │   ├── collections.ts        # Collections
│   │   ├── two-factor.ts         # Two-factor auth
│   │   ├── webauthn.ts           # Passkeys
│   │   ├── auth-requests.ts      # Passwordless login
│   │   ├── sends.ts              # Secure sharing
│   │   ├── devices.ts            # Device management
│   │   ├── events.ts             # Audit logs
│   │   ├── settings.ts           # User settings
│   │   ├── reports.ts            # Security reports
│   │   ├── icons.ts              # Website icons
│   │   ├── config.ts             # Server config
│   │   └── tasks.ts              # Scheduled tasks
│   ├── services/                 # Business logic
│   │   ├── icons/                # Icon fetching, caching, security checks
│   │   ├── crypto.ts             # Encryption utilities
│   │   ├── totp.ts               # TOTP verification
│   │   ├── scheduled.ts          # Cron job handlers
│   │   ├── events.ts             # Event logging
│   │   ├── policy-validators.ts  # Policy validation
│   │   └── signup-guard.ts       # Registration control
│   ├── middleware/               # Middleware
│   │   ├── auth.ts               # JWT authentication
│   │   ├── error.ts              # Error handling
│   │   └── debug.ts              # Debug logging
│   ├── durable-objects/          # Durable Objects
│   ├── db/                       # Drizzle database schema
│   ├── models/                   # Response models
│   └── types/                    # TypeScript type definitions
├── drizzle/                      # SQL migration files
├── .github/workflows/deploy.yml  # CI/CD automated deployment
├── wrangler.toml                 # Workers deployment config
├── tsconfig.json
└── package.json
```

---

## Security

- **End-to-end encryption**: All vault data is encrypted on the client — the server only stores ciphertext.
- **Password hashing**: PBKDF2-SHA256, consistent with the official Bitwarden implementation.
- **JWT signing**: HMAC-SHA256. `JWT_SECRET` must be set to a strong random value via `wrangler secret put`.
- **Token rotation**: Refresh tokens are automatically rotated after each use.
- **Anti-enumeration**: The prelogin endpoint returns default KDF parameters even for non-existent users.
- **Registration protection**: Default `auto` mode automatically disables open registration after the first user signs up.
- **SSRF protection**: The Icons service blocks direct IP access, internal addresses, and non-standard ports.

---

## License

AGPL-3.0
