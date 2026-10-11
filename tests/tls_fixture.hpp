#pragma once
#ifndef APS_BUILD_TESTS
#error "test-only header"
#endif
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace aps::test {
inline void tlsU16(std::vector<uint8_t>& v, size_t n) {
    v.push_back(static_cast<uint8_t>(n >> 8));
    v.push_back(static_cast<uint8_t>(n));
}
inline std::vector<uint8_t> tlsHandshake(const std::string& name,
                                        bool ech = false, bool duplicateSni = false) {
    std::vector<uint8_t> extensions;
    // GREASE extension: unknown values must not hide the subsequent SNI.
    tlsU16(extensions, 0x2a2a);
    tlsU16(extensions, 0);
    if (ech) {
        tlsU16(extensions, 0xfe0d);
        tlsU16(extensions, 3);
        extensions.insert(extensions.end(), {0, 1, 2});
    }
    if (!name.empty()) {
        for (int i = 0; i < (duplicateSni ? 2 : 1); ++i) {
            tlsU16(extensions, 0);
            tlsU16(extensions, name.size() + 5);
            tlsU16(extensions, name.size() + 3);
            extensions.push_back(0);
            tlsU16(extensions, name.size());
            extensions.insert(extensions.end(), name.begin(), name.end());
        }
    }
    std::vector<uint8_t> body{3, 3};
    body.resize(34, 0x42);  // random
    body.push_back(0);      // session ID
    tlsU16(body, 2);
    body.insert(body.end(), {0x13, 1, 1, 0});  // cipher + compression
    tlsU16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());
    std::vector<uint8_t> hello{1, static_cast<uint8_t>(body.size() >> 16),
                             static_cast<uint8_t>(body.size() >> 8),
                             static_cast<uint8_t>(body.size())};
    hello.insert(hello.end(), body.begin(), body.end());
    return hello;
}
inline std::vector<uint8_t> tlsRecords(const std::vector<uint8_t>& hello,
                                      size_t fragment = 16384) {
    std::vector<uint8_t> wire;
    for (size_t pos = 0; pos < hello.size();) {
        const size_t n = std::min(fragment, hello.size() - pos);
        wire.insert(wire.end(), {22, 3, 1});
        tlsU16(wire, n);
        wire.insert(wire.end(), hello.begin() + pos, hello.begin() + pos + n);
        pos += n;
    }
    return wire;
}
inline std::vector<uint8_t> tlsHello(const std::string& name, bool ech = false) {
    return tlsRecords(tlsHandshake(name, ech));
}
}  // namespace aps::test
