#pragma once

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

#include "hash.h"
#include "rsa.h"
#include "wav.h"

// Signs a WAV file's audio in place.
//
// Layout of the data chunk, in samples:
//
//   [ 0, 64 )        the LSB of each sample carries one bit of the signature s,
//                    MSB-first (see lsb.h)
//   [ 64, 192 )      the LSB of each sample carries one bit of the key id
//   [ 192, end )     hashed region
//
// The signature is s = h^d mod n, where h is the SHA-256 of the hashed region
// reduced mod n. The carrier samples are excluded from the hash entirely, so
// writing the signature can never change the value being signed.
//
// The key id is a fingerprint of the signing key's public half: the first
// 16 bytes of SHA-256 over the ASCII text "<n>:<e>" (both decimal). The
// registry stores public keys under this id, so a verifier can look the key
// up and confirm that what came back matches the id in the file.
namespace sochlor::signature
{

inline constexpr size_t signatureBits  = sizeof (uint64_t) * CHAR_BIT;   // 64
inline constexpr size_t keyIdBytes     = 16;
inline constexpr size_t keyIdBits      = keyIdBytes * CHAR_BIT;          // 128
inline constexpr size_t carrierSamples = signatureBits + keyIdBits;      // 192, one bit per sample

using KeyId = std::array<uint8_t, keyIdBytes>;

// Byte offset of the first hashed byte for the given sample width.
constexpr size_t hashOffset (size_t bytesPerSample) { return carrierSamples * bytesPerSample; }

// Fingerprint of a public key, as described above. Fails only if SHA-256 fails.
std::expected<KeyId, std::string> keyIdOf (const rsa::PublicKey& key);

// 32 hex characters <-> KeyId. Use hash::toHex for the other direction.
std::optional<KeyId> keyIdFromHex (std::string_view hex);

// Everything that can be read from a file without knowing the key.
struct Payload
{
    size_t       hashOffset = 0;   // first hashed byte in file.audio
    hash::Sha256 digest {};        // SHA-256 of audio[hashOffset:]
    uint64_t     s = 0;            // carried in samples [0, 64)
    KeyId        keyId {};         // carried in samples [64, 192)
};

// Reads the carriers and hashes the region. Does no key arithmetic.
std::expected<Payload, std::string> extract (const wav::File& file);

struct Signed
{
    Payload  payload;              // as written into the file
    uint64_t h = 0;                // digest reduced mod n
};

// Hashes the audio, signs the digest, and embeds s and keyId in file.audio.
std::expected<Signed, std::string> sign (wav::File& file, const rsa::PrivateKey& key, const KeyId& keyId);

struct Verification
{
    Payload  payload;
    uint64_t h = 0;                    // digest reduced mod n
    uint64_t recovered = 0;            // s^e mod n
    bool     keyIdMatches = false;     // payload.keyId == keyIdOf (key)
    bool     signatureValid = false;   // recovered == h
    bool     valid = false;            // both of the above
};

// Checks an extracted payload against a public key.
std::expected<Verification, std::string> check (const Payload& payload, const rsa::PublicKey& key);

// extract() followed by check().
std::expected<Verification, std::string> verify (const wav::File& file, const rsa::PublicKey& key);

} // namespace sochlor::signature
