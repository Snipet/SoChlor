#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "hash.h"
#include "registry.h"
#include "rsa.h"
#include "signature.h"
#include "wav.h"

using namespace sochlor;

namespace
{

struct Args
{
    std::string              command;
    std::vector<std::string> positional;
    std::string              out;      // -o
    std::string              key;      // -k
    std::string              server;   // --server, default $SOCHLOR_SERVER
    std::string              label;    // --label
    std::string              token;    // --token,  default $SOCHLOR_TOKEN
};

int usage (const char* argv0)
{
    std::cerr << "usage:\n"
              << "  " << argv0 << " keygen   [-o <prefix>]                        write <prefix>.pub and <prefix>.priv (default: key)\n"
              << "  " << argv0 << " register -k <key.priv> --server <url> [--label <text>] [--token <token>]\n"
              << "                                                    store the public key in the registry and stamp its id into <key.priv>\n"
              << "  " << argv0 << " sign     <in.wav> -k <key.priv> -o <out.wav>  key must be registered first\n"
              << "  " << argv0 << " verify   <in.wav> --server <url>              look the key up in the registry; exit 0 if valid, 2 if not\n"
              << "  " << argv0 << " verify   <in.wav> -k <key.pub>                offline, against a public key file\n"
              << "  " << argv0 << " info     <in.wav>\n"
              << "\n"
              << "  --server and --token default to $SOCHLOR_SERVER and $SOCHLOR_TOKEN\n";
    return 1;
}

std::string envOr (const char* name, const std::string& fallback)
{
    const char* value = std::getenv (name);
    return value != nullptr ? value : fallback;
}

std::optional<Args> parseArgs (int argc, char* argv[])
{
    Args args;
    args.server = envOr ("SOCHLOR_SERVER", "");
    args.token  = envOr ("SOCHLOR_TOKEN", "");

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        std::string* option = nullptr;

        if (arg == "-o")            option = &args.out;
        else if (arg == "-k")       option = &args.key;
        else if (arg == "--server") option = &args.server;
        else if (arg == "--label")  option = &args.label;
        else if (arg == "--token")  option = &args.token;

        if (option != nullptr)
        {
            if (++i >= argc)
            {
                std::cerr << arg << " needs a value\n";
                return std::nullopt;
            }

            *option = argv[i];
        }
        else if (args.command.empty())
        {
            args.command = arg;
        }
        else
        {
            args.positional.push_back (arg);
        }
    }

    return args;
}

int fail (const std::string& message)
{
    std::cerr << message << "\n";
    return 1;
}

void printPayload (const signature::Payload& payload)
{
    std::cout << "carrier:       " << signature::carrierSamples << " samples: signature in the LSB of 0.."
              << (signature::signatureBits - 1) << ", key id in " << signature::signatureBits << ".."
              << (signature::carrierSamples - 1) << "\n"
              << "hash offset:   " << payload.hashOffset << " bytes (carrier samples are not hashed)\n"
              << "sha-256:       " << hash::toHex (payload.digest) << "\n"
              << "key id:        " << hash::toHex (payload.keyId) << "\n"
              << "signature s:   " << payload.s << "\n";
}

void printKey (const rsa::PublicKey& key, const std::string& label)
{
    std::cout << "n:             " << key.n << "\n"
              << "e:             " << key.e << "\n";

    if (! label.empty())
        std::cout << "label:         " << label << "\n";
}

// ---- keygen [-o <prefix>] ----
int cmdKeygen (const Args& args, const char* argv0)
{
    if (! args.positional.empty() || ! args.key.empty())
        return usage (argv0);

    const std::string prefix = args.out.empty() ? "key" : args.out;
    const rsa::KeyPair keys  = rsa::generateKeyPair();
    const auto keyId         = signature::keyIdOf (keys.pub);

    if (! keyId)
        return fail (keyId.error());

    if (auto saved = rsa::savePublicKey (keys.pub, prefix + ".pub"); ! saved)
        return fail (saved.error());

    if (auto saved = rsa::savePrivateKey (keys.priv, prefix + ".priv"); ! saved)
        return fail (saved.error());

    printKey (keys.pub, "");
    std::cout << "key id:        " << hash::toHex (*keyId) << " (run `register` before signing)\n"
              << "wrote:         " << prefix << ".pub\n"
              << "wrote:         " << prefix << ".priv (keep private)\n";
    return 0;
}

// ---- register -k <key.priv> --server <url> [--label <text>] ----
int cmdRegister (const Args& args, const char* argv0)
{
    if (! args.positional.empty() || args.key.empty() || ! args.out.empty())
        return usage (argv0);

    auto key = rsa::loadPrivateKey (args.key);

    if (! key)
        return fail (key.error());

    const auto localId = signature::keyIdOf (key->publicKey());

    if (! localId)
        return fail (localId.error());

    const registry::Client client { args.server, args.token };
    const auto record = registry::registerKey (client, key->publicKey(), args.label);

    if (! record)
        return fail (record.error());

    // The registry derives the id from the same fingerprint; anything else
    // means we are talking to something that is not a SoChlor registry.
    if (record->keyId != *localId)
        return fail ("registry returned key id " + hash::toHex (record->keyId)
                     + " but the local fingerprint is " + hash::toHex (*localId));

    key->keyId = hash::toHex (record->keyId);

    if (auto saved = rsa::savePrivateKey (*key, args.key); ! saved)
        return fail (saved.error());

    printKey (record->key, record->label);
    std::cout << "key id:        " << key->keyId << "\n"
              << "registered:    " << args.server << (record->createdAt.empty() ? "" : " (since " + record->createdAt + ")") << "\n"
              << "updated:       " << args.key << "\n";
    return 0;
}

// ---- info <in.wav> ----
int cmdInfo (const Args& args, const char* argv0)
{
    if (args.positional.size() != 1 || ! args.out.empty() || ! args.key.empty())
        return usage (argv0);

    const auto file = wav::read (args.positional[0]);

    if (! file)
        return fail (file.error());

    wav::printInfo (*file, std::cout);
    return 0;
}

// ---- sign <in.wav> -k <key.priv> -o <out.wav> ----
int cmdSign (const Args& args, const char* argv0)
{
    if (args.positional.size() != 1 || args.key.empty() || args.out.empty())
        return usage (argv0);

    const auto key = rsa::loadPrivateKey (args.key);

    if (! key)
        return fail (key.error());

    if (key->keyId.empty())
        return fail (args.key + " is not registered: run `register -k " + args.key + " --server <url>` first");

    const auto keyId   = signature::keyIdFromHex (key->keyId);
    const auto localId = signature::keyIdOf (key->publicKey());

    if (! localId)
        return fail (localId.error());

    if (! keyId || *keyId != *localId)
        return fail (args.key + ": the stored key id does not match this key; register it again");

    auto file = wav::read (args.positional[0]);

    if (! file)
        return fail (file.error());

    wav::printInfo (*file, std::cout);

    const auto result = signature::sign (*file, *key, *keyId);

    if (! result)
        return fail (result.error());

    printPayload (result->payload);
    std::cout << "h = sha mod n: " << result->h << "\n";

    if (auto written = wav::write (*file, args.out); ! written)
        return fail (written.error());

    std::cout << "wrote:         " << args.out << "\n";
    return 0;
}

int reportVerdict (uint64_t h, uint64_t recovered, bool keyIdMatches, bool valid, const std::string& source)
{
    std::cout << "h = sha mod n: " << h << "\n"
              << "s^e mod n:     " << recovered << "\n"
              << "key id match:  " << (keyIdMatches ? "yes" : "no") << "\n"
              << "result:        " << (valid ? "VALID" : "INVALID") << " (" << source << ")\n";
    return valid ? 0 : 2;
}

// ---- verify <in.wav> (--server <url> | -k <key.pub>) ----
int cmdVerify (const Args& args, const char* argv0)
{
    const bool offline = ! args.key.empty();

    if (args.positional.size() != 1 || ! args.out.empty() || (offline && ! args.server.empty() && args.server != envOr ("SOCHLOR_SERVER", "")))
        return usage (argv0);

    const auto file = wav::read (args.positional[0]);

    if (! file)
        return fail (file.error());

    wav::printInfo (*file, std::cout);

    const auto payload = signature::extract (*file);

    if (! payload)
        return fail (payload.error());

    printPayload (*payload);

    if (offline)
    {
        const auto key = rsa::loadPublicKey (args.key);

        if (! key)
            return fail (key.error());

        const auto result = signature::check (*payload, *key);

        if (! result)
            return fail (result.error());

        printKey (*key, "");
        return reportVerdict (result->h, result->recovered, result->keyIdMatches, result->valid, "offline, " + args.key);
    }

    const registry::Client client { args.server, args.token };
    const auto remote = registry::verify (client, *payload);

    if (! remote)
        return fail (remote.error());

    if (! remote->keyFound)
    {
        std::cout << "result:        INVALID (registry " << args.server << ": " << remote->reason << ")\n";
        return 2;
    }

    // Cross-check the registry: the key it used must match the id in the
    // file, and its verdict must agree with the arithmetic done locally.
    const auto local = signature::check (*payload, remote->key.key);

    if (! local)
        return fail (local.error());

    if (! local->keyIdMatches)
        return fail ("registry returned a key whose fingerprint does not match the key id in the file");

    if (local->valid != remote->valid || local->h != remote->h || local->recovered != remote->recovered)
        return fail ("registry verdict disagrees with local arithmetic; refusing to trust it");

    printKey (remote->key.key, remote->key.label);
    return reportVerdict (remote->h, remote->recovered, local->keyIdMatches, remote->valid, "registry " + args.server);
}

} // namespace

int main (int argc, char* argv[])
{
    const std::optional<Args> args = parseArgs (argc, argv);

    if (! args)
        return 1;

    if (args->command == "keygen")   return cmdKeygen   (*args, argv[0]);
    if (args->command == "register") return cmdRegister (*args, argv[0]);
    if (args->command == "info")     return cmdInfo     (*args, argv[0]);
    if (args->command == "sign")     return cmdSign     (*args, argv[0]);
    if (args->command == "verify")   return cmdVerify   (*args, argv[0]);

    if (! args->command.empty())
        std::cerr << "unknown command: " << args->command << "\n";

    return usage (argv[0]);
}
