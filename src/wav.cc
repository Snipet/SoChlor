#include "wav.h"

#include <cstring>
#include <fstream>

namespace sochlor::wav
{

namespace
{
    // ---- little-endian readers over a byte buffer ----
    uint16_t rd16 (const uint8_t* p) { return uint16_t (p[0] | (p[1] << 8)); }

    uint32_t rd32 (const uint8_t* p)
    {
        return uint32_t (p[0]) | (uint32_t (p[1]) << 8)
             | (uint32_t (p[2]) << 16) | (uint32_t (p[3]) << 24);
    }
} // namespace

uint64_t File::frames() const
{
    return format.blockAlign ? audio.size() / format.blockAlign : 0;
}

double File::lengthSeconds() const
{
    return format.sampleRate ? double (frames()) / format.sampleRate : 0.0;
}

const char* formatName (uint16_t tag)
{
    switch (tag)
    {
        case 0x0001: return "PCM integer";
        case 0x0003: return "IEEE float";
        case 0x0006: return "A-law";
        case 0x0007: return "mu-law";
        case 0xFFFE: return "EXTENSIBLE";
        default:     return "unknown";
    }
}

std::expected<File, std::string> read (const std::string& path)
{
    std::ifstream f (path, std::ios::binary);

    if (! f)
        return std::unexpected ("could not open: " + path);

    // ---- RIFF header ----
    uint8_t riff[12];

    if (! f.read (reinterpret_cast<char*> (riff), 12))
        return std::unexpected ("file too short");

    if (std::memcmp (riff, "RIFF", 4) != 0 || std::memcmp (riff + 8, "WAVE", 4) != 0)
        return std::unexpected ("not a RIFF/WAVE file");

    // ---- walk chunks, seeking past everything we don't need ----
    File file;
    file.sourcePath = path;
    Format& fmt = file.format;

    uint32_t dataSize = 0;
    bool haveFmt = false, haveData = false;

    uint8_t header[8];

    while (f.read (reinterpret_cast<char*> (header), 8))
    {
        const uint32_t chunkSize = rd32 (header + 4);
        const std::streamoff payload = f.tellg();

        if (std::memcmp (header, "fmt ", 4) == 0 && chunkSize >= 16)
        {
            std::vector<uint8_t> chunk (chunkSize);

            if (! f.read (reinterpret_cast<char*> (chunk.data()), chunkSize))
                break;

            fmt.formatTag     = rd16 (chunk.data());
            fmt.numChannels   = rd16 (chunk.data() + 2);
            fmt.sampleRate    = rd32 (chunk.data() + 4);
            fmt.blockAlign    = rd16 (chunk.data() + 12);
            fmt.bitsPerSample = rd16 (chunk.data() + 14);
            fmt.validBits     = fmt.bitsPerSample;

            // EXTENSIBLE: real format code lives in the first 2 bytes of the GUID
            if (fmt.formatTag == 0xFFFE && chunkSize >= 40)
            {
                fmt.validBits = rd16 (chunk.data() + 18);
                fmt.formatTag = rd16 (chunk.data() + 24);
            }

            haveFmt = true;
        }
        else if (std::memcmp (header, "data", 4) == 0)
        {
            file.dataOffset = payload;
            dataSize        = chunkSize;
            haveData        = true;
        }

        if (haveFmt && haveData)
            break;

        // chunks are word-aligned: odd sizes carry a pad byte
        f.seekg (payload + std::streamoff (chunkSize) + (chunkSize & 1), std::ios::beg);
    }

    if (! haveFmt || ! haveData)
        return std::unexpected ("missing fmt or data chunk");

    // ---- clamp against real file length (streamed files often lie) ----
    f.clear();
    f.seekg (0, std::ios::end);
    const std::streamoff fileEnd = f.tellg();
    const uint64_t available = uint64_t (fileEnd - file.dataOffset);

    if (dataSize == 0 || dataSize > available)
        dataSize = uint32_t (available);

    // ---- read ONLY the audio payload ----
    file.audio.resize (dataSize);
    f.seekg (file.dataOffset, std::ios::beg);

    if (! f.read (reinterpret_cast<char*> (file.audio.data()), dataSize))
        return std::unexpected ("short read on data chunk");

    if (fmt.blockAlign == 0)
        fmt.blockAlign = uint16_t (fmt.numChannels * (fmt.bitsPerSample / 8));

    return file;
}

std::expected<void, std::string> write (const File& file, const std::string& outPath)
{
    // Truncating the output would destroy the source before we copy it.
    if (outPath == file.sourcePath)
        return std::unexpected ("refusing to overwrite the source file in place: " + outPath);

    std::ifstream in (file.sourcePath, std::ios::binary);

    if (! in)
        return std::unexpected ("could not open: " + file.sourcePath);

    // The patch must land inside the original data chunk.
    in.seekg (0, std::ios::end);
    const std::streamoff sourceEnd = in.tellg();
    in.seekg (0, std::ios::beg);

    if (file.dataOffset + std::streamoff (file.audio.size()) > sourceEnd)
        return std::unexpected ("audio buffer is larger than the source data chunk");

    std::ofstream out (outPath, std::ios::binary | std::ios::trunc);

    if (! out)
        return std::unexpected ("could not open for writing: " + outPath);

    out << in.rdbuf();           // byte-for-byte copy: keeps every other chunk
    out.flush();

    out.seekp (file.dataOffset, std::ios::beg);
    out.write (reinterpret_cast<const char*> (file.audio.data()),
               static_cast<std::streamsize> (file.audio.size()));
    out.flush();

    if (! out)
        return std::unexpected ("write failed: " + outPath);

    return {};
}

void printInfo (const File& file, std::ostream& out)
{
    const Format& fmt = file.format;
    const std::ios_base::fmtflags saved (out.flags());

    out << "file:          " << file.sourcePath << "\n"
        << "format:        " << formatName (fmt.formatTag)
        << " (0x" << std::hex << fmt.formatTag << std::dec << ")\n"
        << "sample rate:   " << fmt.sampleRate << " Hz\n"
        << "channels:      " << fmt.numChannels << "\n"
        << "bits/sample:   " << fmt.bitsPerSample;

    if (fmt.validBits != fmt.bitsPerSample)
        out << " (" << fmt.validBits << " valid)";

    out << "\n"
        << "block align:   " << fmt.blockAlign << " bytes/frame\n"
        << "data offset:   " << file.dataOffset << "\n"
        << "audio bytes:   " << file.audio.size() << "\n"
        << "frames:        " << file.frames() << "\n"
        << "length:        " << file.lengthSeconds() << " s\n";

    out.flags (saved);
}

} // namespace sochlor::wav
