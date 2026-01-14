# OAuth Settings (Google & Apple)

This project supports OAuth login via **Google** and **Apple**.

For Google, credentials are stored as **role-scoped OAuth profiles** identified by a stable **`key`** (e.g. `customer`, `axis`). The UI selects which profile to use by calling the backend with `:oauthKey`.

Secrets are stored **encrypted at rest**.

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

## Google OAuth profiles (recommended)

Google OAuth is configured via **profiles**. Each profile has:

- `key`: stable identifier used by clients (e.g. `customer`, `axis`)
- `callbackUrl`: should match `APP_URL/auth/<key>/google/callback`
- `clientId`
- `clientSecret` (encrypted; never returned)
- `allowedRoles`: role roots permitted to use this profile (descendants allowed)
- `allowedDomains` (optional): list of allowed email domains

### Create a Google profile

- `POST /api/v1/settings/oauth/google/profiles`

Body (example):

```json
{
  "key": "axis",
  "clientId": "1234567890-abc123def456.apps.googleusercontent.com",
  "callbackUrl": "https://api.example.com/auth/axis/google/callback",
  "allowedRoleIds": ["<admin-role-id>", "<super-admin-role-id>"],
  "allowedDomains": ["example.com"]
}
```

### Set the Google client secret (encrypted)

- `POST /api/v1/settings/oauth/google/profiles/:id/secret`

```json
{
  "clientSecret": "<google-client-secret>"
}
```

### Read Google profiles

- `GET /api/v1/settings/oauth/google/profiles`
- `GET /api/v1/settings/oauth/google/profiles/:id`
- `GET /api/v1/settings/oauth/google/profiles/key/:key`

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

## Google OAuth login (backend-only, key-driven)

Google OAuth is handled entirely by the backend using a **one-time exchange code** flow.

### 1) Initiate OAuth

- `GET /auth/:oauthKey/google`

Optional query:

- `redirect=/relative/path` (only same-origin relative paths are accepted)

Example:

- `GET https://api.example.com/auth/axis/google?redirect=/auth/callback`

### 2) Callback

- `GET /auth/:oauthKey/google/callback`

On success, the backend:

- creates/links the user
- issues a short-lived **`exchangeCode`** (single-use)
- redirects back to `redirect` with `?exchangeCode=...`

If no `redirect` was provided, the callback responds with JSON containing `{ exchangeCode }`.

### 3) Exchange for tokens

- `POST /auth/oauth/exchange`

Body:

```json
{
  "exchangeCode": "..."
}
```

Response:

```json
{
  "data": {
    "accessToken": "...",
    "refreshToken": "..."
  }
}
```

Exchange code properties:

- short TTL (about 60s)
- single-use (consumed on exchange)

---

## Apple OAuth

Apple OAuth remains available via the versioned API auth controller.

- Initiate: `GET /api/v1/auth/apple` or `GET /api/v1/auth/:oauthKey/apple`
- Callback: `POST /api/v1/auth/apple/callback` or `POST /api/v1/auth/:oauthKey/apple/callback`

Apple can also be configured via profiles:

- `GET /api/v1/settings/oauth/apple/profiles`
- `POST /api/v1/settings/oauth/apple/profiles`
- `POST /api/v1/settings/oauth/apple/profiles/:id/secret`
