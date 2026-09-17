#pragma once

#include <cstdint>
#include <expected>
#include <ios>
#include <ostream>
#include <string>
#include <vector>

namespace sochlor::wav
{

// Contents of the "fmt " chunk. For WAVE_FORMAT_EXTENSIBLE files the real
// format code is unwrapped from the sub-format GUID, so `formatTag` is always
// the effective encoding.
struct Format
{
    uint16_t formatTag     = 0;
    uint16_t numChannels   = 0;
    uint32_t sampleRate    = 0;
    uint16_t blockAlign    = 0;   // bytes per frame (all channels)
    uint16_t bitsPerSample = 0;   // container size
    uint16_t validBits     = 0;   // == bitsPerSample unless EXTENSIBLE says otherwise

    size_t bytesPerSample() const { return bitsPerSample / 8; }
};

// A parsed WAV file. `audio` holds the raw interleaved little-endian sample
// bytes of the data chunk and nothing else. Every other chunk is left alone
// on disk and preserved verbatim by write().
struct File
{
    std::string          sourcePath;
    Format               format;
    std::streamoff       dataOffset = 0;   // byte offset of the data chunk payload
    std::vector<uint8_t> audio;

    uint64_t frames() const;
    double   lengthSeconds() const;
};

const char* formatName (uint16_t tag);

// Parses the RIFF header and walks the chunk list until both "fmt " and
// "data" have been seen. The data size is clamped to the real file length
// since streamed files often lie about it.
std::expected<File, std::string> read (const std::string& path);

// Copies the source file byte-for-byte to `outPath`, then overwrites the data
// chunk payload with `file.audio`. The buffer must not have grown past the
// size read() produced.
std::expected<void, std::string> write (const File& file, const std::string& outPath);

// Human-readable summary, one field per line.
void printInfo (const File& file, std::ostream& out);

} // namespace sochlor::wav
