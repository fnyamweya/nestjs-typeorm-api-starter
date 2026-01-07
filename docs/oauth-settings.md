# OAuth Settings (Google & Apple)

This project supports **Admin OAuth** login via Google and Apple.

You can configure credentials in two ways:

1) **Environment variables** (traditional `.env`)
2) **Database-backed Settings** via the Settings API (**recommended**) — secrets are encrypted at rest.

The OAuth strategies resolve credentials in this order:

- **DB Settings first**
- fallback to **env vars**

If credentials are missing, the OAuth endpoints will return **503 Service Unavailable** with a clear message.

---

## Prerequisites

### 1) Encryption key (required for DB secrets)

To store secrets (Google client secret, Apple private key) securely in the database, you must set:

```env
ENCRYPTION_KEY=<a-long-random-string>
```

Notes:

- The app encrypts secrets using AES-256-GCM.
- If `ENCRYPTION_KEY` changes, previously stored secrets cannot be decrypted. You must re-save the secrets.

### 2) Admin auth

All Settings endpoints are protected by:

- JWT auth
- Permissions via `RequirePermissions`

You’ll need a valid admin access token with `SETTINGS:read` and/or `SETTINGS:update`.

---

## Base URL

- Global prefix: `/api`
- URI versioning: `/v1`

So Settings endpoints are under:

- `/api/v1/settings/...`

---

## Google OAuth settings

### Configure non-secret fields

Endpoint:

- `POST /api/v1/settings/oauth/google`

Body:

```json
{
  "clientId": "1234567890-abc123def456.apps.googleusercontent.com",
  "callbackUrl": "https://api.example.com/api/auth/admin/google/callback"
}
```

### Configure secret (encrypted)

Endpoint:

- `POST /api/v1/settings/oauth/google/secret`

Body:

```json
{
  "clientSecret": "<google-client-secret>"
}
```

Response:

- The secret is **never returned**.
- The response includes `hasClientSecret: true|false`.

### Read current configuration

Endpoint:

- `GET /api/v1/settings/oauth/google`

---

## Apple OAuth settings

### Configure non-secret fields

Endpoint:

- `POST /api/v1/settings/oauth/apple`

Body:

```json
{
  "clientId": "com.example.admin",
  "teamId": "ABCDE12345",
  "keyId": "XYZ9876543",
  "callbackUrl": "https://api.example.com/api/auth/admin/apple/callback"
}
```

### Configure secret (encrypted)

Endpoint:

- `POST /api/v1/settings/oauth/apple/secret`

Body:

```json
{
  "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

Response:

- The private key is **never returned**.
- The response includes `hasPrivateKey: true|false`.

### Read current configuration

Endpoint:

- `GET /api/v1/settings/oauth/apple`

---

## Example cURL

Replace `<TOKEN>` with an admin JWT.

```bash
curl -X POST \
  "http://localhost:8090/api/v1/settings/oauth/google" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"clientId":"...","callbackUrl":"http://localhost:8090/api/auth/admin/google/callback"}'
```

```bash
curl -X POST \
  "http://localhost:8090/api/v1/settings/oauth/google/secret" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"clientSecret":"..."}'
```

---

## OAuth login endpoints

Once configured, admin OAuth flows are initiated at:

- Google:
  - `GET /api/auth/admin/google`
  - `GET /api/auth/admin/google/callback`
- Apple:
  - `GET /api/auth/admin/apple`
  - `GET /api/auth/admin/apple/callback`

If credentials are missing, these routes return **503** rather than silently misbehaving.

---

## Environment variable fallback (optional)

If you prefer env vars instead of DB Settings, configure:

```env
APP_URL=http://localhost:8090

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=http://localhost:8090/api/auth/admin/google/callback

APPLE_CLIENT_ID=
APPLE_TEAM_ID=
APPLE_KEY_ID=
APPLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
APPLE_CALLBACK_URL=http://localhost:8090/api/auth/admin/apple/callback
```
