#include "aps/tls_client_hello.hpp"

#include <algorithm>
#include <string_view>
#include <vector>

namespace aps::tls {
namespace {
size_t u16(const uint8_t* p) {
    return (static_cast<size_t>(p[0]) << 8) | p[1];
}
size_t u24(const uint8_t* p) {
    return (static_cast<size_t>(p[0]) << 16) | u16(p + 1);
}

bool hostname(std::string_view name) {
    if (name.empty() || name.size() > 253) return false;
    size_t label = 0;
    bool numeric = true;
    for (size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        if (c == '.') {
            if (label == 0 || name[i - 1] == '-') return false;
            label = 0;
            continue;
        }
        const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        const bool digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '-') return false;
        if (label == 0 && c == '-') return false;
        if (++label > 63) return false;
        if (!digit) numeric = false;
    }
    // Literal IP addresses are not SNI hostnames (RFC 6066 section 3).
    return label != 0 && name.back() != '-' && !numeric;
}

ClientHelloName parseHello(const std::vector<uint8_t>& hello) {
    // Handshake header + legacy version + random + session-id length.
    if (hello.size() < 39 || hello[4] != 3) return {};
    size_t pos = 38;
    const size_t session = hello[pos++];
    if (session > 32 || session > hello.size() - pos) return {};
    pos += session;
    if (hello.size() - pos < 2) return {};
    const size_t ciphers = u16(hello.data() + pos);
    pos += 2;
    if (ciphers < 2 || ciphers % 2 != 0 || ciphers > hello.size() - pos) return {};
    pos += ciphers;
    if (pos == hello.size()) return {};
    const size_t compression = hello[pos++];
    if (compression == 0 || compression > hello.size() - pos) return {};
    pos += compression;
    if (hello.size() - pos < 2) return {};
    const size_t extensions = u16(hello.data() + pos);
    pos += 2;
    if (extensions != hello.size() - pos) return {};

    std::string name;
    bool seenSni = false;
    while (pos < hello.size()) {
        if (hello.size() - pos < 4) return {};
        const size_t type = u16(hello.data() + pos);
        const size_t len = u16(hello.data() + pos + 2);
        pos += 4;
        if (len > hello.size() - pos) return {};
        if (type == 0) {
            if (seenSni || len < 2) return {};
            seenSni = true;
            const size_t end = pos + len;
            if (u16(hello.data() + pos) != len - 2) return {};
            size_t p = pos + 2;
            while (p < end) {
                if (end - p < 3) return {};
                const uint8_t nameType = hello[p++];
                const size_t nameLen = u16(hello.data() + p);
                p += 2;
                if (nameLen == 0 || nameLen > end - p) return {};
                if (nameType == 0) {
                    if (!name.empty()) return {};
                    name.assign(reinterpret_cast<const char*>(hello.data() + p), nameLen);
                    if (!hostname(name)) return {};
                    std::transform(name.begin(), name.end(), name.begin(), [](char c) {
                        return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
                    });
                }
                p += nameLen;
            }
        }
        pos += len;
    }
    return name.empty() ? ClientHelloName{} : ClientHelloName{HelloState::Name, name};
}
}  // namespace

ClientHelloName inspectClientHello(const uint8_t* data, size_t size) {
    if (size > kMaxClientHelloBytes || (size != 0 && data == nullptr)) return {};
    std::vector<uint8_t> hello;
    size_t pos = 0;
    size_t wanted = 0;
    while (pos < size) {
        if (data[pos] != 22) return {};  // handshake record only
        if (size - pos >= 2 && data[pos + 1] != 3) return {};
        if (size - pos >= 3 && data[pos + 2] > 4) return {};
        if (size - pos < 5) return {HelloState::NeedMore, {}};
        const size_t recordLen = u16(data + pos + 3);
        if (recordLen == 0 || recordLen > 16384) return {};
        if (recordLen > size - pos - 5) {
            return size == kMaxClientHelloBytes ? ClientHelloName{}
                                               : ClientHelloName{HelloState::NeedMore, {}};
        }
        const uint8_t* payload = data + pos + 5;
        hello.insert(hello.end(), payload, payload + recordLen);
        if (!hello.empty() && hello[0] != 1) return {};  // ClientHello
        if (hello.size() >= 4 && wanted == 0) {
            wanted = u24(hello.data() + 1) + 4;
            if (wanted > kMaxClientHelloBytes || wanted < 39) return {};
        }
        if (wanted != 0 && hello.size() >= wanted) {
            hello.resize(wanted);
            return parseHello(hello);
        }
        pos += 5 + recordLen;
    }
    return size == kMaxClientHelloBytes ? ClientHelloName{}
                                       : ClientHelloName{HelloState::NeedMore, {}};
}

}  // namespace aps::tls
