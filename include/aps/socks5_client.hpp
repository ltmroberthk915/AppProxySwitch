// SOCKS5 (RFC 1928) client handshake with optional RFC 1929 auth.
#pragma once

#include "aps/net.hpp"

#include <cstdint>
#include <string>

namespace aps {

// Structured cause for a failed SOCKS5 CONNECT.  Callers that drive recovery
// must not infer this from human-readable error text: only ProxyEndpoint means
// the configured local listener/port itself needs to be rediscovered.
enum class Socks5FailureKind {
    None,
    ProxyEndpoint,
    Tunnel,
    Configuration,
    Internal,
};

class Socks5Client {
public:
    // Connect to `proxy` and issue CONNECT for `dst`. On success `outSock` is
    // a connected, tunnel-ready socket. Timeout applies to each phase.
    static bool connect(const net::Endpoint4& proxy, const std::string& username,
                        const std::string& password, const net::Endpoint4& dst,
                        int timeoutMs, SOCKET& outSock, std::string* err,
                        Socks5FailureKind* failureKind = nullptr);

    // ATYP=DOMAIN: let the selected proxy resolve and route the domain.
    // No local name lookup and no fallback to another proxy or destination.
    static bool connectDomain(const net::Endpoint4& proxy,
                              const std::string& username,
                              const std::string& password,
                              const std::string& hostname, uint16_t port,
                              int timeoutMs, SOCKET& outSock, std::string* err,
                              Socks5FailureKind* failureKind = nullptr);

    // Cheap health probe: TCP connect + method negotiation, no CONNECT.
    // Returns latency in ms via `latencyMs` when non-null.
    static bool probe(const net::Endpoint4& proxy, int timeoutMs, int* latencyMs,
                      std::string* err, const std::string& username = {},
                      const std::string& password = {});
};

}  // namespace aps
