#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sochlor::hash
{

inline constexpr size_t sha256Bytes = 32;
using Sha256 = std::array<uint8_t, sha256Bytes>;

// SHA-256 over a memory chunk (OpenSSL EVP). Returns nullopt only if OpenSSL
// itself fails, e.g. on allocation failure.
std::optional<Sha256> sha256 (std::span<const uint8_t> data);

// Lower-case hex, two characters per byte, no separators.
std::string toHex (std::span<const uint8_t> bytes);

// Inverse of toHex; accepts either case. nullopt on odd length or bad chars.
std::optional<std::vector<uint8_t>> fromHex (std::string_view hex);

} // namespace sochlor::hash
