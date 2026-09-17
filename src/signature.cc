#include "signature.h"

#include <algorithm>
#include <span>
#include <vector>

#include "lsb.h"

namespace sochlor::signature
{

namespace
{
    constexpr size_t signatureBytes = signatureBits / CHAR_BIT;
    constexpr size_t carrierBytes   = signatureBytes + keyIdBytes;
    static_assert (carrierBytes * CHAR_BIT == carrierSamples);

    std::array<uint8_t, signatureBytes> toBigEndian (uint64_t value)
    {
        std::array<uint8_t, signatureBytes> bytes;

        for (size_t i = 0; i < signatureBytes; ++i)
            bytes[i] = uint8_t (value >> (CHAR_BIT * (signatureBytes - 1 - i)));

        return bytes;
    }

    uint64_t fromBigEndian (std::span<const uint8_t> bytes)
    {
        uint64_t value = 0;

        for (uint8_t b : bytes)
            value = (value << CHAR_BIT) | b;

        return value;
    }
} // namespace

std::expected<KeyId, std::string> keyIdOf (const rsa::PublicKey& key)
{
    const std::string canonical = std::to_string (key.n) + ":" + std::to_string (key.e);
    const auto bytes  = std::span<const uint8_t> (reinterpret_cast<const uint8_t*> (canonical.data()), canonical.size());
    const auto digest = hash::sha256 (bytes);

    if (! digest)
        return std::unexpected ("sha-256 failed");

    KeyId id;
    std::copy_n (digest->begin(), keyIdBytes, id.begin());
    return id;
}

std::optional<KeyId> keyIdFromHex (std::string_view hex)
{
    const auto bytes = hash::fromHex (hex);

    if (! bytes || bytes->size() != keyIdBytes)
        return std::nullopt;

    KeyId id;
    std::copy_n (bytes->begin(), keyIdBytes, id.begin());
    return id;
}

std::expected<Payload, std::string> extract (const wav::File& file)
{
    const size_t bytesPerSample = file.format.bytesPerSample();

    if (bytesPerSample == 0)
        return std::unexpected ("bit depth below 8 not supported");

    Payload payload;
    payload.hashOffset = hashOffset (bytesPerSample);

    if (file.audio.size() <= payload.hashOffset)
        return std::unexpected ("audio too short: need more than "
                                + std::to_string (payload.hashOffset) + " bytes to carry a signature, have "
                                + std::to_string (file.audio.size()));

    const auto region = std::span<const uint8_t> (file.audio).subspan (payload.hashOffset);
    const auto digest = hash::sha256 (region);

    if (! digest)
        return std::unexpected ("sha-256 failed");

    payload.digest = *digest;

    const std::vector<uint8_t> carried = lsb::extract (file.audio, carrierSamples, bytesPerSample);
    payload.s = fromBigEndian (std::span<const uint8_t> (carried).first (signatureBytes));
    std::copy_n (carried.begin() + signatureBytes, keyIdBytes, payload.keyId.begin());

    return payload;
}

std::expected<Signed, std::string> sign (wav::File& file, const rsa::PrivateKey& key, const KeyId& keyId)
{
    if (key.n < 2)
        return std::unexpected ("invalid key: modulus must be at least 2");

    // Whatever the carriers held before is irrelevant: only the digest matters.
    auto payload = extract (file);

    if (! payload)
        return std::unexpected (payload.error());

    Signed result;
    result.h          = rsa::reduceDigest (payload->digest, key.n);
    payload->s        = rsa::sign (result.h, key);
    payload->keyId    = keyId;

    std::array<uint8_t, carrierBytes> carriers;
    const auto sBytes = toBigEndian (payload->s);
    std::copy (sBytes.begin(), sBytes.end(), carriers.begin());
    std::copy (keyId.begin(), keyId.end(), carriers.begin() + signatureBytes);

    lsb::embed (file.audio, carriers, file.format.bytesPerSample());

    result.payload = *payload;
    return result;
}

std::expected<Verification, std::string> check (const Payload& payload, const rsa::PublicKey& key)
{
    if (key.n < 2)
        return std::unexpected ("invalid key: modulus must be at least 2");

    const auto expectedId = keyIdOf (key);

    if (! expectedId)
        return std::unexpected (expectedId.error());

    Verification result;
    result.payload        = payload;
    result.keyIdMatches   = (*expectedId == payload.keyId);
    result.h              = rsa::reduceDigest (payload.digest, key.n);
    result.recovered      = rsa::powMod (payload.s, key.e, key.n);
    result.signatureValid = rsa::verify (result.h, payload.s, key);
    result.valid          = result.keyIdMatches && result.signatureValid;
    return result;
}

std::expected<Verification, std::string> verify (const wav::File& file, const rsa::PublicKey& key)
{
    const auto payload = extract (file);

    if (! payload)
        return std::unexpected (payload.error());

    return check (*payload, key);
}

} // namespace sochlor::signature
