// Textbook RSA arithmetic over BigInt. Mirrors sochlor::rsa on the client.

export function powMod(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Registry id of a public key: the first 16 bytes of SHA-256 over the ASCII
// text "<n>:<e>" with both numbers in decimal. Must match
// sochlor::signature::keyIdOf in the CLI.
export async function keyIdOf(n: bigint, e: bigint): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${n}:${e}`));
  return toHex(new Uint8Array(digest, 0, 16));
}

export interface SignatureCheck {
  h: bigint;         // digest reduced mod n
  recovered: bigint; // s^e mod n
  valid: boolean;    // recovered === h
}

export function checkSignature(digestHex: string, s: bigint, n: bigint, e: bigint): SignatureCheck {
  const h = BigInt('0x' + digestHex) % n;
  const recovered = powMod(s, e, n);
  return { h, recovered, valid: recovered === h };
}
