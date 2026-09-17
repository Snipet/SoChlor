#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

// Textbook RSA over 64-bit integers, following the "Operation" section of
// https://en.wikipedia.org/wiki/RSA_cryptosystem:
//
//   key generation:  n = p*q,  lambda = lcm(p-1, q-1),  d = e^-1 mod lambda
//   signing:         s = h^d mod n
//   verifying:       s^e mod n == h
//
// This is the arithmetic core only. Moduli are tiny, there is no padding, and
// nothing is constant-time, so it is NOT a secure implementation.
namespace sochlor::rsa
{

struct PublicKey
{
    uint64_t n = 0;
    uint64_t e = 0;
};

struct PrivateKey
{
    uint64_t n = 0;
    uint64_t e = 0;   // kept so the public half can always be recovered
    uint64_t d = 0;

    // Registry id assigned by `SoChlor register` (32 hex chars). Empty until
    // the key has been registered. Not used by the arithmetic.
    std::string keyId;

    PublicKey publicKey() const { return { n, e }; }
};

struct KeyPair
{
    PublicKey  pub;
    PrivateKey priv;
};

// ---- modular arithmetic (all require m > 0) ----

// (a * b) mod m without intermediate overflow.
uint64_t mulMod (uint64_t a, uint64_t b, uint64_t m);

// base^exp mod m by square-and-multiply.
uint64_t powMod (uint64_t base, uint64_t exp, uint64_t m);

uint64_t gcd (uint64_t a, uint64_t b);
uint64_t lcm (uint64_t a, uint64_t b);

// a^-1 mod m via the extended Euclidean algorithm. nullopt if gcd(a, m) != 1.
std::optional<uint64_t> modInverse (uint64_t a, uint64_t m);

// Deterministic Miller-Rabin; exact for every 64-bit n.
bool isProbablePrime (uint64_t n);

// ---- keys ----

// Builds a key pair from two distinct primes and a public exponent. Fails if
// p or q is not prime, p*q overflows 64 bits, or gcd(e, lambda(n)) != 1.
std::optional<KeyPair> makeKeyPair (uint64_t p, uint64_t q, uint64_t e = 65537);

// Picks two random distinct primes in [2^31, 2^32) from the OS entropy source,
// so n is 62..64 bits, and derives the key pair. Retries until it succeeds.
KeyPair generateKeyPair (uint64_t e = 65537);

// ---- key files ----
//
// Plain text: a tag line, then "<label> <value>" lines in any order.
//
//   sochlor-rsa-public-key        sochlor-rsa-private-key
//   n <decimal>                   n <decimal>
//   e <decimal>                   e <decimal>
//                                 d <decimal>
//                                 id <hex>        (present once registered)
//
// The private key file is created with owner-only permissions.

std::expected<void, std::string> savePublicKey  (const PublicKey& key,  const std::string& path);
std::expected<void, std::string> savePrivateKey (const PrivateKey& key, const std::string& path);

std::expected<PublicKey,  std::string> loadPublicKey  (const std::string& path);
std::expected<PrivateKey, std::string> loadPrivateKey (const std::string& path);

// ---- signing ----

// Interprets a big-endian byte string (e.g. a SHA-256 digest) as an integer
// and reduces it mod n so it can be passed to sign() / verify().
uint64_t reduceDigest (std::span<const uint8_t> digest, uint64_t n);

// s = h^d mod n
uint64_t sign (uint64_t h, const PrivateKey& key);

// s^e mod n == h
bool verify (uint64_t h, uint64_t s, const PublicKey& key);

} // namespace sochlor::rsa
