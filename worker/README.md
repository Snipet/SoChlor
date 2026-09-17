# sochlor-registry

Cloudflare Worker + D1 that stores SoChlor public keys and verifies signatures,
so a listener only needs the signed WAV, not a `.pub` file.

## Endpoints

| Method | Path         | Body                              | Returns                                      |
|--------|--------------|-----------------------------------|----------------------------------------------|
| POST   | `/keys`      | `{ "n", "e", "label"? }`          | key record. 201 if new, 200 if already known |
| GET    | `/keys/:id`  |                                   | key record, or 404                           |
| POST   | `/verify`    | `{ "keyId", "digest", "signature" }` | `{ "valid": bool, ...key record, "h", "recovered" }` |

Numbers are decimal strings, `keyId` is 32 hex chars, `digest` is 64 hex chars.
The key id is the first 16 bytes of SHA-256 over `"<n>:<e>"`, computed on both
sides, so registering the same key twice returns the same record.

If the `REGISTER_TOKEN` secret is set, `POST /keys` requires
`Authorization: Bearer <token>`. Verification is always open.

## Run locally

```
npm install
npm run migrate:local
npm run dev                      # http://localhost:8787
```

## Deploy

```
npx wrangler login
npm run deploy                   # first deploy provisions the D1 database and writes its id into wrangler.jsonc
npm run migrate:remote
npx wrangler secret put REGISTER_TOKEN   # optional
```

Then point the CLI at it: `export SOCHLOR_SERVER=https://sochlor-registry.<you>.workers.dev`.
