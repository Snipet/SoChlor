cmake_minimum_required(VERSION 4.3.3)
project(SoChlor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# 1. Find the OpenSSL package (SHA-256) and libcurl (registry client)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)


add_executable(SoChlor
    src/main.cc
    src/wav.cc          # RIFF/WAVE parsing, data-chunk patching
    src/hash.cc         # SHA-256 (OpenSSL EVP), hex formatting
    src/rsa.cc          # modular arithmetic, key generation, key files, sign/verify
    src/lsb.cc          # LSB bit embedding / extraction over PCM
    src/signature.cc    # hash-with-offset + RSA signature + key id embedded in the audio
    src/registry.cc     # HTTP client for the Cloudflare Worker registry (worker/)
)
target_link_libraries(SoChlor PRIVATE OpenSSL::Crypto OpenSSL::SSL CURL::libcurl)
target_include_directories(SoChlor PRIVATE include)
