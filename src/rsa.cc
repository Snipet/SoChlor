#include "rsa.h"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <random>
#include <sstream>

namespace sochlor::rsa
{

using u128 = unsigned __int128;

uint64_t mulMod (uint64_t a, uint64_t b, uint64_t m)
{
    return uint64_t ((u128 (a) * b) % m);
}

uint64_t powMod (uint64_t base, uint64_t exp, uint64_t m)
{
    if (m == 1)
        return 0;

    uint64_t result = 1;
    base %= m;

    while (exp > 0)
    {
        if (exp & 1)
            result = mulMod (result, base, m);

        base = mulMod (base, base, m);
        exp >>= 1;
    }

    return result;
}

uint64_t gcd (uint64_t a, uint64_t b)
{
    while (b != 0)
    {
        const uint64_t r = a % b;
        a = b;
        b = r;
    }

    return a;
}

uint64_t lcm (uint64_t a, uint64_t b)
{
    if (a == 0 || b == 0)
        return 0;

    return (a / gcd (a, b)) * b;
}

std::optional<uint64_t> modInverse (uint64_t a, uint64_t m)
{
    if (m == 0)
        return std::nullopt;

    // Iterative extended Euclid, tracking only the coefficient of `a`.
    // Coefficients are bounded by m, so a signed 128-bit accumulator is safe.
    __int128 t = 0, nextT = 1;
    uint64_t r = m,  nextR = a % m;

    while (nextR != 0)
    {
        const uint64_t q = r / nextR;

        const __int128 tmpT = t - __int128 (q) * nextT;
        t = nextT;
        nextT = tmpT;

        const uint64_t tmpR = r - q * nextR;
        r = nextR;
        nextR = tmpR;
    }

    if (r != 1)
        return std::nullopt;   // not invertible

    if (t < 0)
        t += m;

    return uint64_t (t);
}

bool isProbablePrime (uint64_t n)
{
    if (n < 2)
        return false;

    // These bases make Miller-Rabin deterministic for all n < 2^64.
    static constexpr uint64_t bases[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };

    for (uint64_t p : bases)
        if (n % p == 0)
            return n == p;

    // write n - 1 as d * 2^r with d odd
    uint64_t d = n - 1;
    int r = 0;

    while ((d & 1) == 0)
    {
        d >>= 1;
        ++r;
    }

    for (uint64_t a : bases)
    {
        uint64_t x = powMod (a, d, n);

        if (x == 1 || x == n - 1)
            continue;

        bool composite = true;

        for (int i = 1; i < r; ++i)
        {
            x = mulMod (x, x, n);

            if (x == n - 1)
            {
                composite = false;
                break;
            }
        }

        if (composite)
            return false;
    }

    return true;
}

std::optional<KeyPair> makeKeyPair (uint64_t p, uint64_t q, uint64_t e)
{
    if (p == q || ! isProbablePrime (p) || ! isProbablePrime (q))
        return std::nullopt;

    const u128 n128 = u128 (p) * q;

    if (n128 > std::numeric_limits<uint64_t>::max())
        return std::nullopt;

    const uint64_t n      = uint64_t (n128);
    const uint64_t lambda = lcm (p - 1, q - 1);   // Carmichael's totient

    if (e <= 1 || e >= lambda || gcd (e, lambda) != 1)
        return std::nullopt;

    const std::optional<uint64_t> d = modInverse (e, lambda);

    if (! d)
        return std::nullopt;

    KeyPair keys;
    keys.pub  = { n, e };
    keys.priv = { .n = n, .e = e, .d = *d };
    return keys;
}

namespace
{
    constexpr const char* publicTag  = "sochlor-rsa-public-key";
    constexpr const char* privateTag = "sochlor-rsa-private-key";

    using Fields = std::map<std::string, std::string>;

    // Uniform over the odd numbers in [2^31, 2^32), tested until prime.
    uint64_t randomPrime32 (std::random_device& device)
    {
        for (;;)
        {
            const uint64_t candidate = uint64_t (device()) | 0x80000001u;   // top bit and low bit set

            if (isProbablePrime (candidate))
                return candidate;
        }
    }

    // Reads "<tag>" then "<label> <value>" lines into a map.
    std::expected<Fields, std::string> loadFields (const std::string& path, const char* tag)
    {
        std::ifstream in (path);

        if (! in)
            return std::unexpected ("could not open: " + path);

        std::string fileTag;

        if (! std::getline (in, fileTag))
            return std::unexpected ("malformed key file: " + path);

        if (fileTag != tag)
            return std::unexpected (path + " is not a " + tag + " file (found \"" + fileTag + "\")");

        Fields fields;
        std::string line;

        while (std::getline (in, line))
        {
            if (line.empty())
                continue;

            std::istringstream parts (line);
            std::string label, value, extra;

            if (! (parts >> label >> value) || (parts >> extra))
                return std::unexpected ("malformed line in " + path + ": " + line);

            fields[label] = value;
        }

        return fields;
    }

    std::expected<uint64_t, std::string> field64 (const Fields& fields, const char* label, const std::string& path)
    {
        const auto it = fields.find (label);

        if (it == fields.end())
            return std::unexpected (path + ": missing field \"" + label + "\"");

        const std::string& text = it->second;
        uint64_t value = 0;
        const auto [end, ec] = std::from_chars (text.data(), text.data() + text.size(), value);

        if (ec != std::errc() || end != text.data() + text.size())
            return std::unexpected (path + ": field \"" + label + "\" is not an unsigned integer");

        return value;
    }
} // namespace

KeyPair generateKeyPair (uint64_t e)
{
    std::random_device device;

    for (;;)
    {
        const uint64_t p = randomPrime32 (device);
        const uint64_t q = randomPrime32 (device);

        // Fails only for p == q or gcd(e, lambda) != 1; both are rare, so retry.
        if (const std::optional<KeyPair> keys = makeKeyPair (p, q, e))
            return *keys;
    }
}

std::expected<void, std::string> savePublicKey (const PublicKey& key, const std::string& path)
{
    std::ofstream out (path, std::ios::trunc);

    if (! out)
        return std::unexpected ("could not open for writing: " + path);

    out << publicTag << "\n"
        << "n " << key.n << "\n"
        << "e " << key.e << "\n";

    if (! out)
        return std::unexpected ("write failed: " + path);

    return {};
}

std::expected<void, std::string> savePrivateKey (const PrivateKey& key, const std::string& path)
{
    {
        std::ofstream out (path, std::ios::trunc);

        if (! out)
            return std::unexpected ("could not open for writing: " + path);

        out << privateTag << "\n"
            << "n " << key.n << "\n"
            << "e " << key.e << "\n"
            << "d " << key.d << "\n";

        if (! key.keyId.empty())
            out << "id " << key.keyId << "\n";

        if (! out)
            return std::unexpected ("write failed: " + path);
    }

    namespace fs = std::filesystem;
    std::error_code ec;
    fs::permissions (path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);

    if (ec)
        return std::unexpected ("could not restrict permissions on " + path + ": " + ec.message());

    return {};
}

std::expected<PublicKey, std::string> loadPublicKey (const std::string& path)
{
    const auto fields = loadFields (path, publicTag);

    if (! fields)
        return std::unexpected (fields.error());

    const auto n = field64 (*fields, "n", path);
    const auto e = field64 (*fields, "e", path);

    if (! n) return std::unexpected (n.error());
    if (! e) return std::unexpected (e.error());

    if (*n < 2 || *e < 2)
        return std::unexpected ("malformed key file: " + path);

    return PublicKey { *n, *e };
}

std::expected<PrivateKey, std::string> loadPrivateKey (const std::string& path)
{
    const auto fields = loadFields (path, privateTag);

    if (! fields)
        return std::unexpected (fields.error());

    const auto n = field64 (*fields, "n", path);
    const auto d = field64 (*fields, "d", path);

    if (! n) return std::unexpected (n.error());
    if (! d) return std::unexpected (d.error());

    // Files written before `e` was recorded always used 65537.
    const auto e = fields->contains ("e") ? field64 (*fields, "e", path)
                                          : std::expected<uint64_t, std::string> (65537);

    if (! e) return std::unexpected (e.error());

    if (*n < 2 || *e < 2 || *d == 0)
        return std::unexpected ("malformed key file: " + path);

    PrivateKey key { .n = *n, .e = *e, .d = *d };

    if (const auto id = fields->find ("id"); id != fields->end())
        key.keyId = id->second;

    return key;
}

uint64_t reduceDigest (std::span<const uint8_t> digest, uint64_t n)
{
    // Horner's rule, big-endian: h = (h * 256 + byte) mod n
    uint64_t h = 0;

    for (uint8_t b : digest)
        h = uint64_t ((u128 (h) * 256 + b) % n);

    return h;
}

uint64_t sign (uint64_t h, const PrivateKey& key)
{
    return powMod (h, key.d, key.n);
}

bool verify (uint64_t h, uint64_t s, const PublicKey& key)
{
    return powMod (s, key.e, key.n) == h % key.n;
}

} // namespace sochlor::rsa
