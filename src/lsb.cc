#include "lsb.h"

#include <cassert>
#include <climits>

namespace sochlor::lsb
{

void clear (std::span<uint8_t> audio, size_t bitCount, size_t bytesPerSample)
{
    assert (audio.size() >= bytesNeeded (bitCount, bytesPerSample));

    for (size_t i = 0; i < bitCount; ++i)
        audio[carrierByte (i, bytesPerSample)] &= static_cast<uint8_t> (~1u);
}

void embed (std::span<uint8_t> audio, std::span<const uint8_t> payload, size_t bytesPerSample)
{
    const size_t bitCount = payload.size() * CHAR_BIT;
    assert (audio.size() >= bytesNeeded (bitCount, bytesPerSample));

    for (size_t i = 0; i < bitCount; ++i)
    {
        const uint8_t bit = (payload[i / CHAR_BIT] >> (CHAR_BIT - 1 - (i % CHAR_BIT))) & 0x01;
        uint8_t& carrier  = audio[carrierByte (i, bytesPerSample)];

        carrier = static_cast<uint8_t> ((carrier & ~1u) | bit);
    }
}

std::vector<uint8_t> extract (std::span<const uint8_t> audio, size_t bitCount, size_t bytesPerSample)
{
    assert (audio.size() >= bytesNeeded (bitCount, bytesPerSample));

    std::vector<uint8_t> payload ((bitCount + CHAR_BIT - 1) / CHAR_BIT, 0);

    for (size_t i = 0; i < bitCount; ++i)
    {
        const uint8_t bit = audio[carrierByte (i, bytesPerSample)] & 0x01;
        payload[i / CHAR_BIT] |= static_cast<uint8_t> (bit << (CHAR_BIT - 1 - (i % CHAR_BIT)));
    }

    return payload;
}

} // namespace sochlor::lsb
