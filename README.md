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

## Demo

Everything below runs from the repo root against a registry on your own
machine, so no Cloudflare account is needed. Once the worker is deployed, point
`SOCHLOR_SERVER` at it instead and the commands are the same.

**1. Build the CLI**

```
cmake -S . -B build && cmake --build build
```

**2. Start a local registry** in a second terminal and leave it running.

```
cd worker
npm install
npm run migrate:local          # creates the `keys` table in a local D1
npm run dev                    # serves http://localhost:8787
```

Back in the first terminal:

```
export SOCHLOR_SERVER=http://localhost:8787
mkdir demo                     # gitignored scratch space
```

**3. Make a key.** The key id is a fingerprint of the public half, so it is
known before anything is registered.

```
$ ./build/SoChlor keygen -o demo/key
n:             12258506047952470519
e:             65537
key id:        22bf00f0cd1d5c756bef82312f532e90 (run `register` before signing)
wrote:         demo/key.pub
wrote:         demo/key.priv (keep private)
```

**4. Register it.** The public half goes to the registry, the id comes back,
and it is written into `demo/key.priv`. If the registry has a
`REGISTER_TOKEN`, add `--token <token>` or set `SOCHLOR_TOKEN`.

```
$ ./build/SoChlor register -k demo/key.priv --label "demo studio"
n:             12258506047952470519
e:             65537
label:         demo studio
key id:        22bf00f0cd1d5c756bef82312f532e90
registered:    http://localhost:8787 (since 2026-09-17T12:47:02Z)
updated:       demo/key.priv
```

**5. Sign a file.** The first 192 samples become carriers; everything after
them is hashed.

```
$ ./build/SoChlor sign assets/sample_song.wav -k demo/key.priv -o demo/signed.wav
file:          assets/sample_song.wav
format:        PCM integer (0x1)
sample rate:   44100 Hz
channels:      2
bits/sample:   24
block align:   6 bytes/frame
data offset:   80
audio bytes:   78503100
frames:        13083850
length:        296.686 s
carrier:       192 samples: signature in the LSB of 0..63, key id in 64..191
hash offset:   576 bytes (carrier samples are not hashed)
sha-256:       9e6afb35d9c3fa291c618feb77009f4b44d8bc1ef652e6890b813c1517bc5d53
key id:        22bf00f0cd1d5c756bef82312f532e90
signature s:   2312763830187440040
h = sha mod n: 1810229769295901786
wrote:         demo/signed.wav
```

**6. Verify it with nothing but the file.** The CLI reads the key id out of
the audio and sends it, the digest, and `s` to the registry, which looks the
key up and checks `s^e mod n == h`. Exit status 0 means valid.

```
$ ./build/SoChlor verify demo/signed.wav
...
key id:        22bf00f0cd1d5c756bef82312f532e90
signature s:   2312763830187440040
n:             12258506047952470519
e:             65537
label:         demo studio
h = sha mod n: 1810229769295901786
s^e mod n:     1810229769295901786
key id match:  yes
result:        VALID (registry http://localhost:8787)
$ echo $?
0
```

**7. Tamper with it.** One byte changed deep in the audio gives a different
hash, so the recovered value no longer matches. Exit status 2.

```
$ cp demo/signed.wav demo/tampered.wav
$ printf '\xff' | dd of=demo/tampered.wav bs=1 seek=5000 conv=notrunc status=none
$ ./build/SoChlor verify demo/tampered.wav
...
sha-256:       d463b23e07c88a9d5734828fb1d4ce11ea9bc8624a439fd28cd21ef57d9c7bda
h = sha mod n: 3062755117140454639
s^e mod n:     1810229769295901786
key id match:  yes
result:        INVALID (registry http://localhost:8787)
$ echo $?
2
```

**8. An unsigned file** carries no key id, only whatever bits the audio
happened to have, so the registry has nothing to look up.

```
$ ./build/SoChlor verify assets/sample_song.wav
...
key id:        af815f482b98a3ade0c869c7930c2c73
result:        INVALID (registry http://localhost:8787: unknown key id)
```

**9. Offline check** against the `.pub` file, with no registry involved.

```
$ ./build/SoChlor verify demo/signed.wav -k demo/key.pub
...
result:        VALID (offline, demo/key.pub)
```

**10. What got stored.** The private key file now carries the id, and the
registry serves the public key under it.

```
$ cat demo/key.priv
sochlor-rsa-private-key
n 12258506047952470519
e 65537
d 245634413296205465
id 22bf00f0cd1d5c756bef82312f532e90

$ curl -s $SOCHLOR_SERVER/keys/22bf00f0cd1d5c756bef82312f532e90
{"keyId":"22bf00f0cd1d5c756bef82312f532e90","n":"12258506047952470519","e":"65537","label":"demo studio","createdAt":"2026-09-17T12:47:02Z"}
```

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
