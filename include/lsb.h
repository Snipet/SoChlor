#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// Bit-level steganography over interleaved little-endian PCM.
//
// Bit i of a payload lives in the least-significant bit of sample i. Samples
// are little-endian, so the LSB of sample i is its FIRST byte, at offset
// i * bytesPerSample -- true for 16/24/32-bit int, and for IEEE float the low
// mantissa bit is also byte 0. Bits are taken MSB-first within each payload
// byte; extract() uses the same order.
namespace sochlor::lsb
{

// Byte index of the carrier bit for sample `sampleIndex`.
constexpr size_t carrierByte (size_t sampleIndex, size_t bytesPerSample)
{
    return sampleIndex * bytesPerSample;
}

// Bytes of audio needed to hold `bitCount` bits.
constexpr size_t bytesNeeded (size_t bitCount, size_t bytesPerSample)
{
    return bitCount == 0 ? 0 : carrierByte (bitCount - 1, bytesPerSample) + 1;
}

// Zeroes the carrier bits of the first `bitCount` samples. Do this before
// hashing so a reader can repeat the masking, re-hash, and compare.
void clear (std::span<uint8_t> audio, size_t bitCount, size_t bytesPerSample);

// Writes every bit of `payload` into the carrier bits (sets or clears each).
void embed (std::span<uint8_t> audio, std::span<const uint8_t> payload, size_t bytesPerSample);

// Reads `bitCount` bits back out; the result holds ceil(bitCount / 8) bytes.
std::vector<uint8_t> extract (std::span<const uint8_t> audio, size_t bitCount, size_t bytesPerSample);

} // namespace sochlor::lsb
