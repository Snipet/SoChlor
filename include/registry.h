#pragma once

#include <cstdint>
#include <expected>
#include <string>

#include "rsa.h"
#include "signature.h"

// HTTP client for the sochlor-registry Cloudflare Worker (see worker/).
// Public keys live in its D1 database under their key id, so a verifier only
// needs the signed file: it reads the key id out of the audio and asks the
// registry to check the signature.
namespace sochlor::registry
{

struct Client
{
    std::string baseUrl;   // e.g. https://sochlor-registry.example.workers.dev
    std::string token;     // optional bearer token; only needed to register
};

struct KeyRecord
{
    signature::KeyId keyId {};
    rsa::PublicKey   key;
    std::string      label;
    std::string      createdAt;
};

// POST /keys. Idempotent: registering a known key returns its existing record.
std::expected<KeyRecord, std::string> registerKey (const Client& client, const rsa::PublicKey& key,
                                                   const std::string& label);

// GET /keys/<id>
std::expected<KeyRecord, std::string> fetchKey (const Client& client, const signature::KeyId& keyId);

struct RemoteVerification
{
    bool        keyFound = false;   // false: the registry has no key with this id
    bool        valid    = false;   // the registry's verdict
    std::string reason;             // set when keyFound is false
    KeyRecord   key;                // the key the registry used (when found)
    uint64_t    h = 0;              // digest reduced mod n, as computed by the registry
    uint64_t    recovered = 0;      // s^e mod n, as computed by the registry
};

// POST /verify with a payload extracted from a file.
std::expected<RemoteVerification, std::string> verify (const Client& client, const signature::Payload& payload);

} // namespace sochlor::registry
