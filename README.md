# Aionima Local-ID

OAuth credential broker and identity service for self-hosted Aionima nodes. Manages user accounts, entity identity (GEID), OAuth token storage, and federation with the Aionima network.

**Mode:** Local (single-tenant, runs on the owner's node alongside AGI)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| HTTP | Hono |
| Auth | Lucia (sessions) + Argon2 (passwords) |
| Database | PostgreSQL via Drizzle ORM |
| Encryption | AES-256-GCM (tokens, GEID private keys) |
| Federation | Ed25519 signatures (Mycelium-Sig) |

---

## Architecture

### Authentication Tiers (fallback order)

1. **Private network** — RFC 1918 IP ranges auto-identify as owner (no login required on LAN)
2. **Node API key** — `Authorization: Bearer <OWNER_NODE_API_KEY>` for AGI gateway calls
3. **Mycelium-Sig** — Ed25519 signature header for federated node-to-node auth
4. **Session cookie** — Lucia cookie-based sessions for browser access
5. **Anonymous** — unauthenticated (limited access)

### Route Groups

| Route | Purpose |
|-------|---------|
| `/auth` | Register, login, logout |
| `/api/entities` | Entity CRUD, register-owner (genesis), bind-agent |
| `/api/connections` | OAuth connection list/delete |
| `/api/handoff` | Token delivery mechanism (create, approve, poll) |
| `/api/users` | User management (owner-only) |
| `/api/oauth/delegate` | Proxy OAuth flows through Hive-ID |
| `/dashboard` | HTML UI for managing service connections |
| `/channels` | Channel setup wizard (Telegram, Discord) |
| `/settings` | Provider settings, Hive-ID health check |
| `/federation` | GEID verify, whoami, `.well-known/mycelium-node.json` |

### Handoff Mechanism

Local-ID runs on a private LAN and can't receive OAuth callbacks from public providers. The handoff protocol solves this with a 3-step flow:

1. **Create** — AGI gateway requests a handoff, gets a `handoffId` + `authUrl`
2. **Approve** — User visits the URL, logs in (or auto-approves on LAN), snapshots OAuth tokens
3. **Poll** — AGI polls for the result using the 256-bit handoff ID as credential (one-time delivery)

Handoffs expire after 15 minutes. A background job cleans up expired entries every 60 seconds.

### Entity System

| Type | Prefix | Example |
|------|--------|---------|
| Individual | `#E` / `~E` | `#E0` (genesis owner) |
| Organization | `#O` / `~O` | `#O0` (primary org) |
| Team | `#T` / `~T` | `#E0~T0` (team under owner) |
| Family | `#F` / `~F` | `#F0` |
| Agent | `$A` / `~A` | `$A0` (primary agent) |

- **Genesis onboarding** creates `#E0` (owner) + `$A0` (agent) with Ed25519 keypair
- **GEID format:** `geid:<base58-public-key>`
- **Scope:** `local` (~prefix) for unregistered, `registered` (#/$ prefix) for HIVE-registered

### OAuth Delegation

Local-ID does not run its own OAuth providers. All OAuth flows (Google, GitHub, Discord) are delegated through **Hive-ID** (`https://id.aionima.ai`), which handles the public callback URLs. Tokens are encrypted and stored locally after delegation completes.

---

## Database

9 tables managed by Drizzle ORM:

| Table | Purpose |
|-------|---------|
| `users` | User accounts (email, password hash, dashboard role) |
| `sessions` | Lucia session tokens |
| `entities` | Entity registry (type, COA alias, verification tier) |
| `geidLocal` | Ed25519 keypairs per entity (encrypted) |
| `agentBindings` | Link agent entities to owners |
| `registrations` | Audit trail (on-chain ready) |
| `connections` | OAuth tokens (encrypted) |
| `handoffs` | Temporary token delivery records |

---

## Environment Variables

```bash
# Required
DATABASE_URL=postgres://user:pass@localhost:5432/aionima_id
ENCRYPTION_KEY=          # 64-char hex (32 bytes) — generate with:
                         # node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# OAuth (delegated through Hive-ID in local mode)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# AGI gateway connection (local mode)
OWNER_NODE_URL=          # e.g. http://localhost:3100
OWNER_NODE_API_KEY=      # shared secret with AGI gateway

# Optional
PORT=3000                # HTTP listen port
NODE_ENV=production      # enables secure cookies
HIVE_ID_URL=https://id.aionima.ai
```

---

## Development

```bash
# Install dependencies
npm install

# Generate database migrations
npm run db:generate

# Apply migrations
npm run db:migrate

# Start dev server (hot-reload)
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

---

## Deployment

In production, Local-ID runs as a systemd service managed by AGI's `upgrade.sh`. The service unit file is at `aionima-id.service` in the repo root.

```bash
# Service management
sudo systemctl status aionima-id
sudo systemctl restart aionima-id
```

Migrations run automatically at startup via `start.sh` (Docker entrypoint).

---

## Federation

Local-ID participates in the Aionima federation network:

- **Node manifest:** `GET /.well-known/mycelium-node.json` — advertises capabilities
- **GEID verify:** `GET /federation/verify?geid=<geid>` — verify entity identity (uses cached Hive-ID snapshot for offline capability)
- **Whoami:** `GET /federation/whoami` — returns authenticated entity info

A background job fetches Hive-ID's GEID registry snapshot every 5 minutes, enabling offline federation verification when the central service is unreachable.

---

## Security

- AES-256-GCM encryption for tokens and GEID private keys
- CSRF protection (double-submit cookies)
- HTML escaping for XSS prevention
- Rate limiting: login (5/min), register (3/min), handoff (10/min)
- Private-network auto-auth (no credentials needed on LAN)
- One-time handoff delivery (256-bit random ID)
- Argon2 password hashing
