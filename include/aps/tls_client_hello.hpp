// Bounded, passive ClientHello inspection. Never changes TLS bytes or
// validates certificates; the caller must independently authorize a name
// before using it as a SOCKS destination.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace aps::tls {

constexpr size_t kMaxClientHelloBytes = 64 * 1024;
enum class HelloState { NeedMore, NoName, Name };
struct ClientHelloName {
    HelloState state = HelloState::NoName;
    std::string name;
};

// Accepts complete or fragmented TLS records from the beginning of a TCP
// stream. Malformed/oversized input, non-TLS and missing SNI return NoName.
ClientHelloName inspectClientHello(const uint8_t* data, size_t size);

}  // namespace aps::tls
