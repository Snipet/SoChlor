#include "hash.h"

#include <algorithm>

#include <openssl/evp.h>

namespace sochlor::hash
{

std::optional<Sha256> sha256 (std::span<const uint8_t> data)
{
    unsigned char buffer[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr)
        return std::nullopt;

    const bool ok = EVP_DigestInit_ex (context, EVP_sha256(), nullptr) == 1
                 && EVP_DigestUpdate (context, data.data(), data.size()) == 1
                 && EVP_DigestFinal_ex (context, buffer, &length) == 1;

    EVP_MD_CTX_free (context);

    if (! ok || length != sha256Bytes)
        return std::nullopt;

    Sha256 digest;
    std::copy_n (buffer, sha256Bytes, digest.begin());
    return digest;
}

std::string toHex (std::span<const uint8_t> bytes)
{
    static constexpr char digits[] = "0123456789abcdef";

    std::string s;
    s.reserve (bytes.size() * 2);

    for (uint8_t b : bytes)
    {
        s.push_back (digits[b >> 4]);
        s.push_back (digits[b & 0x0F]);
    }

    return s;
}

namespace
{
    int nibble (char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
} // namespace

std::optional<std::vector<uint8_t>> fromHex (std::string_view hex)
{
    if (hex.size() % 2 != 0)
        return std::nullopt;

    std::vector<uint8_t> bytes;
    bytes.reserve (hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = nibble (hex[i]);
        const int lo = nibble (hex[i + 1]);

        if (hi < 0 || lo < 0)
            return std::nullopt;

        bytes.push_back (static_cast<uint8_t> ((hi << 4) | lo));
    }

    return bytes;
}

} // namespace sochlor::hash
