-- Public keys, addressed by the 128-bit fingerprint that SoChlor embeds in
-- signed audio (first 16 bytes of SHA-256 over "<n>:<e>", hex encoded).
-- n and e are stored as decimal text so moduli wider than 64 bits fit later.
CREATE TABLE IF NOT EXISTS keys (
  id         TEXT PRIMARY KEY,
  n          TEXT NOT NULL,
  e          TEXT NOT NULL,
  label      TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
