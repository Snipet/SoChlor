// SoChlor registry: stores public keys in D1 and verifies signatures.
//
//   GET  /              endpoint listing
//   POST /keys          register { n, e, label? }        -> key record (201 new, 200 existing)
//   GET  /keys/:id      fetch a key record
//   POST /verify        { keyId, digest, signature }     -> { valid, ... }
//
// All numbers travel as decimal strings; ids and digests as lower-case hex.

import { checkSignature, keyIdOf } from './rsa';

const MAX_BODY_BYTES = 8 * 1024;
const MAX_LABEL_CHARS = 200;
const DECIMAL = /^[1-9][0-9]{0,1233}$/; // positive, no leading zeros, up to ~4096 bits
const DECIMAL_OR_ZERO = /^(0|[1-9][0-9]{0,1233})$/;
const KEY_ID = /^[0-9a-f]{32}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

interface KeyRow {
  id: string;
  n: string;
  e: string;
  label: string;
  created_at: string;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function keyRecord(row: KeyRow) {
  return { keyId: row.id, n: row.n, e: row.e, label: row.label, createdAt: row.created_at };
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  const length = request.headers.get('content-length');
  if (length === null) throw new HttpError(411, 'content-length header required');
  if (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES) {
    throw new HttpError(413, `body must be at most ${MAX_BODY_BYTES} bytes`);
  }

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    throw new HttpError(400, 'body must be valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, 'body must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

function requireField(body: Record<string, unknown>, field: string, pattern: RegExp, what: string): string {
  const value = body[field];
  if (typeof value !== 'string' || !pattern.test(value)) throw new HttpError(400, `${field} must be ${what}`);
  return value;
}

async function timingSafeEquals(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

// Registration is open unless the REGISTER_TOKEN secret is configured.
async function requireRegisterToken(request: Request, env: Env): Promise<void> {
  if (!env.REGISTER_TOKEN) return;
  const header = request.headers.get('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
  if (!(await timingSafeEquals(token, env.REGISTER_TOKEN))) {
    throw new HttpError(401, 'registration requires a valid bearer token');
  }
}

function findKey(env: Env, id: string): Promise<KeyRow | null> {
  return env.DB.prepare('SELECT id, n, e, label, created_at FROM keys WHERE id = ?1').bind(id).first<KeyRow>();
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  await requireRegisterToken(request, env);
  const body = await readJsonBody(request);
  const n = requireField(body, 'n', DECIMAL, 'a positive decimal integer');
  const e = requireField(body, 'e', DECIMAL, 'a positive decimal integer');
  if (BigInt(n) < 3n || BigInt(e) < 2n) throw new HttpError(400, 'n must be at least 3 and e at least 2');

  const label = body['label'] ?? '';
  if (typeof label !== 'string' || label.length > MAX_LABEL_CHARS) {
    throw new HttpError(400, `label must be a string of at most ${MAX_LABEL_CHARS} characters`);
  }

  const id = await keyIdOf(BigInt(n), BigInt(e));
  const existing = await findKey(env, id);
  if (existing) return json(keyRecord(existing), 200);

  // OR IGNORE: a concurrent registration of the same key is not an error.
  await env.DB.prepare('INSERT OR IGNORE INTO keys (id, n, e, label) VALUES (?1, ?2, ?3, ?4)').bind(id, n, e, label).run();
  const row = await findKey(env, id);
  if (!row) throw new HttpError(500, 'key was not stored');
  return json(keyRecord(row), 201);
}

async function handleGetKey(env: Env, id: string): Promise<Response> {
  if (!KEY_ID.test(id)) throw new HttpError(400, 'key id must be 32 lower-case hex characters');
  const row = await findKey(env, id);
  if (!row) throw new HttpError(404, 'unknown key id');
  return json(keyRecord(row));
}

async function handleVerify(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBody(request);
  const keyId = requireField(body, 'keyId', KEY_ID, '32 lower-case hex characters');
  const digest = requireField(body, 'digest', SHA256_HEX, 'a 64-character lower-case hex SHA-256');
  const signature = requireField(body, 'signature', DECIMAL_OR_ZERO, 'a decimal integer');

  const row = await findKey(env, keyId);
  if (!row) throw new HttpError(404, 'unknown key id');

  const { h, recovered, valid } = checkSignature(digest, BigInt(signature), BigInt(row.n), BigInt(row.e));
  return json({ valid, ...keyRecord(row), digest, signature, h: h.toString(), recovered: recovered.toString() });
}

export default {
  async fetch(request, env): Promise<Response> {
    const path = new URL(request.url).pathname.replace(/\/+$/, '') || '/';

    try {
      if (path === '/' && request.method === 'GET') {
        return json({
          service: 'sochlor-registry',
          register: 'POST /keys {n, e, label?}',
          key: 'GET /keys/:id',
          verify: 'POST /verify {keyId, digest, signature}',
        });
      }
      if (path === '/keys' && request.method === 'POST') return await handleRegister(request, env);
      if (path === '/verify' && request.method === 'POST') return await handleVerify(request, env);

      const key = /^\/keys\/([^/]+)$/.exec(path);
      if (key && request.method === 'GET') return await handleGetKey(env, key[1] ?? '');

      throw new HttpError(404, 'not found');
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, error.status);
      console.log(JSON.stringify({ level: 'error', path, message: error instanceof Error ? error.message : String(error) }));
      return json({ error: 'internal error' }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
