# SoChlor

Signs WAV files with RSA and stores the signature inside the audio itself, in
the least-significant bit of the first samples. Public keys live in a
Cloudflare Worker + D1 registry (see [worker/](worker/)), and the audio carries
the id of the key that signed it, so a listener needs nothing but the file.

```
SoChlor keygen   [-o <prefix>]                         write <prefix>.pub and <prefix>.priv (default: key)
SoChlor register -k <key.priv> --server <url> [--label <text>] [--token <token>]
SoChlor sign     <in.wav> -k <key.priv> -o <out.wav>   key must be registered first
SoChlor verify   <in.wav> --server <url>               ask the registry; exit 0 if valid, 2 if not
SoChlor verify   <in.wav> -k <key.pub>                 offline, against a public key file
SoChlor info     <in.wav>
```

`--server` and `--token` default to `$SOCHLOR_SERVER` and `$SOCHLOR_TOKEN`.

## Workflow

```
SoChlor keygen -o mykey
SoChlor register -k mykey.priv --server https://sochlor-registry.<you>.workers.dev --label "my studio"
SoChlor sign "assets/drum beat3.wav" -k mykey.priv -o signed.wav
SoChlor verify signed.wav --server https://sochlor-registry.<you>.workers.dev
```

`register` sends the public half of the key to the registry and writes the
returned key id into `mykey.priv`. `sign` refuses to run until that id is
present, since a signature nobody can look up is useless.

## How a signature is laid out

```
data chunk:  [ samples 0..63 ][ samples 64..191 ][ sample 192 ............... end ]
              LSB = bits of s   LSB = bits of key id   SHA-256 covers exactly this region
```

1. `h` = SHA-256 of the audio bytes starting at sample 192, reduced mod `n`.
   The 192 carrier samples are not hashed at all, so embedding the signature
   cannot change the value being signed.
2. `s = h^d mod n` is written MSB-first into the LSB of samples 0..63, and the
   key id into samples 64..191.
3. To verify, read `s` and the key id back out, fetch the key, recompute `h`
   from the same region, and check `s^e mod n == h`.

The key id is a fingerprint: the first 16 bytes of SHA-256 over the text
`"<n>:<e>"`. The CLI and the worker both compute it, so registering the same
key twice is harmless, and a verifier can confirm that the key the registry
returned really is the one named in the file. The CLI also repeats the RSA
arithmetic locally and refuses a registry verdict that disagrees.

Keys are textbook RSA over 64-bit integers (two random 32-bit primes), which
is enough to exercise the scheme but not secure: a 64-bit modulus can be
factored in seconds. The registry already stores `n` and `e` as decimal text,
so a big-integer `sochlor::rsa` backend is the upgrade path.

## Layout

| Header                 | Source             | Namespace            | Contents                                                          |
|------------------------|--------------------|----------------------|-------------------------------------------------------------------|
| `include/wav.h`        | `src/wav.cc`       | `sochlor::wav`       | RIFF/WAVE parsing (`read`), data-chunk patching (`write`)         |
| `include/hash.h`       | `src/hash.cc`      | `sochlor::hash`      | `sha256` over a byte span, `toHex` / `fromHex`                    |
| `include/rsa.h`        | `src/rsa.cc`       | `sochlor::rsa`       | `mulMod`, `powMod`, `modInverse`, `makeKeyPair`, `generateKeyPair`, key files, `sign`, `verify` |
| `include/lsb.h`        | `src/lsb.cc`       | `sochlor::lsb`       | `clear`, `embed`, `extract` bits in sample LSBs                   |
| `include/signature.h`  | `src/signature.cc` | `sochlor::signature` | carrier layout, `keyIdOf`, `extract`, `sign`, `check`, `verify`   |
| `include/registry.h`   | `src/registry.cc`  | `sochlor::registry`  | libcurl client for the worker: `registerKey`, `fetchKey`, `verify` |
| —                      | `src/main.cc`      | —                    | CLI subcommands                                                   |
| `worker/`              |                    |                      | Cloudflare Worker + D1: `POST /keys`, `GET /keys/:id`, `POST /verify` |

## Build

Needs CMake, a C++23 compiler, OpenSSL, and libcurl (all present in the macOS SDK
except OpenSSL, e.g. `brew install openssl`).

```
cmake -S . -B build
cmake --build build
```

For the worker, see [worker/README.md](worker/README.md).
