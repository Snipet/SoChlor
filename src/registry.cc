#include "registry.h"

#include <cctype>
#include <charconv>
#include <cstring>
#include <map>
#include <string_view>

#include <curl/curl.h>

#include "hash.h"

namespace sochlor::registry
{

namespace
{
    // =====================================================================
    //  Minimal JSON: enough for the flat objects the registry exchanges.
    //  Scalars become text ("true"/"false", null -> ""); nested values are
    //  kept as their raw JSON text.
    // =====================================================================
    using Object = std::map<std::string, std::string>;

    std::string jsonString (std::string_view text)
    {
        std::string out = "\"";

        for (const char c : text)
        {
            switch (c)
            {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (static_cast<unsigned char> (c) < 0x20)
                    {
                        char buffer[8];
                        std::snprintf (buffer, sizeof buffer, "\\u%04x", c);
                        out += buffer;
                    }
                    else
                        out += c;
            }
        }

        return out + "\"";
    }

    void appendUtf8 (std::string& out, unsigned code)
    {
        if (code < 0x80)
            out += char (code);
        else if (code < 0x800)
        {
            out += char (0xC0 | (code >> 6));
            out += char (0x80 | (code & 0x3F));
        }
        else
        {
            out += char (0xE0 | (code >> 12));
            out += char (0x80 | ((code >> 6) & 0x3F));
            out += char (0x80 | (code & 0x3F));
        }
    }

    class Parser
    {
    public:
        explicit Parser (std::string_view text) : text (text) {}

        std::expected<Object, std::string> parseObject()
        {
            skipSpace();

            if (! consume ('{'))
                return fail ("expected '{'");

            Object object;
            skipSpace();

            if (consume ('}'))
                return object;

            for (;;)
            {
                skipSpace();
                auto key = parseString();

                if (! key)
                    return std::unexpected (key.error());

                skipSpace();

                if (! consume (':'))
                    return fail ("expected ':'");

                skipSpace();
                auto value = parseValue();

                if (! value)
                    return std::unexpected (value.error());

                object[*key] = *value;
                skipSpace();

                if (consume (','))
                    continue;

                if (consume ('}'))
                    return object;

                return fail ("expected ',' or '}'");
            }
        }

    private:
        std::string_view text;
        size_t pos = 0;

        bool consume (char c)
        {
            if (pos < text.size() && text[pos] == c)
            {
                ++pos;
                return true;
            }

            return false;
        }

        void skipSpace()
        {
            while (pos < text.size() && std::isspace (static_cast<unsigned char> (text[pos])))
                ++pos;
        }

        std::unexpected<std::string> fail (const char* what) const
        {
            return std::unexpected ("malformed JSON at offset " + std::to_string (pos) + ": " + what);
        }

        bool startsWith (const char* literal) const
        {
            return text.substr (pos).starts_with (literal);
        }

        std::expected<std::string, std::string> parseValue()
        {
            if (pos >= text.size())
                return fail ("unexpected end");

            const char c = text[pos];

            if (c == '"')             return parseString();
            if (c == '{' || c == '[') return skipNested();

            if (startsWith ("true"))  { pos += 4; return "true"; }
            if (startsWith ("false")) { pos += 5; return "false"; }
            if (startsWith ("null"))  { pos += 4; return ""; }

            const size_t start = pos;

            while (pos < text.size() && std::strchr ("0123456789+-.eE", text[pos]) != nullptr)
                ++pos;

            if (pos == start)
                return fail ("unexpected character");

            return std::string (text.substr (start, pos - start));
        }

        std::expected<std::string, std::string> parseString()
        {
            if (! consume ('"'))
                return fail ("expected '\"'");

            std::string out;

            while (pos < text.size())
            {
                const char c = text[pos++];

                if (c == '"')
                    return out;

                if (c != '\\')
                {
                    out += c;
                    continue;
                }

                if (pos >= text.size())
                    break;

                const char escape = text[pos++];

                switch (escape)
                {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'u':
                    {
                        if (pos + 4 > text.size())
                            return fail ("bad \\u escape");

                        unsigned code = 0;
                        const char* first = text.data() + pos;
                        const auto [end, ec] = std::from_chars (first, first + 4, code, 16);

                        if (ec != std::errc() || end != first + 4)
                            return fail ("bad \\u escape");

                        pos += 4;
                        appendUtf8 (out, code);
                        break;
                    }
                    default:
                        return fail ("bad escape");
                }
            }

            return fail ("unterminated string");
        }

        std::expected<std::string, std::string> skipNested()
        {
            const size_t start = pos;
            int depth = 0;
            bool inString = false;

            while (pos < text.size())
            {
                const char c = text[pos++];

                if (inString)
                {
                    if (c == '\\')      ++pos;
                    else if (c == '"')  inString = false;
                }
                else if (c == '"')
                    inString = true;
                else if (c == '{' || c == '[')
                    ++depth;
                else if ((c == '}' || c == ']') && --depth == 0)
                    return std::string (text.substr (start, pos - start));
            }

            return fail ("unterminated value");
        }
    };

    std::expected<std::string, std::string> field (const Object& object, const char* name)
    {
        const auto it = object.find (name);

        if (it == object.end())
            return std::unexpected (std::string ("server response is missing \"") + name + "\"");

        return it->second;
    }

    std::expected<uint64_t, std::string> field64 (const Object& object, const char* name)
    {
        const auto text = field (object, name);

        if (! text)
            return std::unexpected (text.error());

        uint64_t value = 0;
        const auto [end, ec] = std::from_chars (text->data(), text->data() + text->size(), value);

        if (ec == std::errc::result_out_of_range)
            return std::unexpected (std::string ("server value \"") + name + "\" does not fit in 64 bits; this client only supports 64-bit keys");

        if (ec != std::errc() || end != text->data() + text->size())
            return std::unexpected (std::string ("server value \"") + name + "\" is not an unsigned integer: " + *text);

        return value;
    }

    std::expected<KeyRecord, std::string> toKeyRecord (const Object& object)
    {
        const auto idText = field (object, "keyId");
        const auto n      = field64 (object, "n");
        const auto e      = field64 (object, "e");

        if (! idText) return std::unexpected (idText.error());
        if (! n)      return std::unexpected (n.error());
        if (! e)      return std::unexpected (e.error());

        const auto keyId = signature::keyIdFromHex (*idText);

        if (! keyId)
            return std::unexpected ("server returned a malformed key id: " + *idText);

        KeyRecord record;
        record.keyId     = *keyId;
        record.key       = { *n, *e };
        record.label     = field (object, "label").value_or ("");
        record.createdAt = field (object, "createdAt").value_or ("");
        return record;
    }

    // =====================================================================
    //  HTTP via libcurl
    // =====================================================================
    struct HttpResponse
    {
        long        status = 0;
        std::string body;
    };

    size_t appendToString (char* data, size_t size, size_t count, void* userdata)
    {
        static_cast<std::string*> (userdata)->append (data, size * count);
        return size * count;
    }

    std::string joinUrl (std::string base, const std::string& path)
    {
        while (! base.empty() && base.back() == '/')
            base.pop_back();

        return base + path;
    }

    std::expected<HttpResponse, std::string> request (const Client& client, const char* method,
                                                      const std::string& path, const std::string& body)
    {
        if (client.baseUrl.empty())
            return std::unexpected ("no registry URL: pass --server or set SOCHLOR_SERVER");

        static const bool curlReady = (curl_global_init (CURL_GLOBAL_DEFAULT) == CURLE_OK);

        if (! curlReady)
            return std::unexpected ("curl_global_init failed");

        CURL* curl = curl_easy_init();

        if (curl == nullptr)
            return std::unexpected ("curl_easy_init failed");

        const std::string url = joinUrl (client.baseUrl, path);
        HttpResponse response;
        char errorBuffer[CURL_ERROR_SIZE] = {};

        curl_slist* headers = curl_slist_append (nullptr, "Accept: application/json");

        if (! body.empty())
            headers = curl_slist_append (headers, "Content-Type: application/json");

        std::string authorization;

        if (! client.token.empty())
        {
            authorization = "Authorization: Bearer " + client.token;
            headers = curl_slist_append (headers, authorization.c_str());
        }

        curl_easy_setopt (curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, appendToString);
        curl_easy_setopt (curl, CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt (curl, CURLOPT_ERRORBUFFER, errorBuffer);
        curl_easy_setopt (curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt (curl, CURLOPT_USERAGENT, "SoChlor/0.1");

        if (! body.empty())
        {
            curl_easy_setopt (curl, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, static_cast<long> (body.size()));
        }

        const CURLcode code = curl_easy_perform (curl);

        if (code == CURLE_OK)
            curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response.status);

        curl_slist_free_all (headers);
        curl_easy_cleanup (curl);

        if (code != CURLE_OK)
            return std::unexpected ("request to " + url + " failed: "
                                    + (errorBuffer[0] != '\0' ? errorBuffer : curl_easy_strerror (code)));

        return response;
    }

    std::string serverError (const HttpResponse& response)
    {
        if (const auto object = Parser (response.body).parseObject(); object && object->contains ("error"))
            return object->at ("error");

        return response.body.empty() ? "no response body" : response.body.substr (0, 200);
    }

    // Performs a request and parses the JSON object; any non-2xx status is an error.
    std::expected<Object, std::string> call (const Client& client, const char* method,
                                             const std::string& path, const std::string& body)
    {
        const auto response = request (client, method, path, body);

        if (! response)
            return std::unexpected (response.error());

        if (response->status < 200 || response->status >= 300)
            return std::unexpected ("registry returned HTTP " + std::to_string (response->status) + ": " + serverError (*response));

        auto object = Parser (response->body).parseObject();

        if (! object)
            return std::unexpected ("could not parse registry response: " + object.error());

        return object;
    }
} // namespace

std::expected<KeyRecord, std::string> registerKey (const Client& client, const rsa::PublicKey& key,
                                                   const std::string& label)
{
    const std::string body = "{\"n\":\"" + std::to_string (key.n)
                           + "\",\"e\":\"" + std::to_string (key.e)
                           + "\",\"label\":" + jsonString (label) + "}";

    const auto object = call (client, "POST", "/keys", body);

    if (! object)
        return std::unexpected (object.error());

    return toKeyRecord (*object);
}

std::expected<KeyRecord, std::string> fetchKey (const Client& client, const signature::KeyId& keyId)
{
    const auto object = call (client, "GET", "/keys/" + hash::toHex (keyId), "");

    if (! object)
        return std::unexpected (object.error());

    return toKeyRecord (*object);
}

std::expected<RemoteVerification, std::string> verify (const Client& client, const signature::Payload& payload)
{
    const std::string body = "{\"keyId\":\"" + hash::toHex (payload.keyId)
                           + "\",\"digest\":\"" + hash::toHex (payload.digest)
                           + "\",\"signature\":\"" + std::to_string (payload.s) + "\"}";

    const auto response = request (client, "POST", "/verify", body);

    if (! response)
        return std::unexpected (response.error());

    RemoteVerification result;

    if (response->status == 404)
    {
        result.reason = serverError (*response);
        return result;
    }

    if (response->status < 200 || response->status >= 300)
        return std::unexpected ("registry returned HTTP " + std::to_string (response->status) + ": " + serverError (*response));

    const auto object = Parser (response->body).parseObject();

    if (! object)
        return std::unexpected ("could not parse registry response: " + object.error());

    const auto key       = toKeyRecord (*object);
    const auto valid     = field (*object, "valid");
    const auto h         = field64 (*object, "h");
    const auto recovered = field64 (*object, "recovered");

    if (! key)       return std::unexpected (key.error());
    if (! valid)     return std::unexpected (valid.error());
    if (! h)         return std::unexpected (h.error());
    if (! recovered) return std::unexpected (recovered.error());

    result.keyFound  = true;
    result.valid     = (*valid == "true");
    result.key       = *key;
    result.h         = *h;
    result.recovered = *recovered;
    return result;
}

} // namespace sochlor::registry
