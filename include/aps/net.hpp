// Small Winsock helpers shared by the SOCKS5 client, relay and tests.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <string>

namespace aps::net {

// Host-byte-order IPv4 endpoint.
struct Endpoint4 {
    uint32_t ip = 0;
    uint16_t port = 0;
    bool operator==(const Endpoint4& o) const { return ip == o.ip && port == o.port; }
};

// One-time Winsock init (reference counted); call from every process entry.
bool initWinsock();
void cleanupWinsock();

// Bind a UDP socket and let the stack pick the port (for test helpers).
SOCKET makeTcpSocket();
void closeSocket(SOCKET& s);

// Non-blocking connect with timeout. Returns 0 on success, -1 on error
// (err filled), -2 on timeout. The socket is returned to blocking mode.
int connectWithTimeout(SOCKET s, const Endpoint4& dst, int timeoutMs, std::string* err);

// select()-based send of the whole buffer. 0 ok, -1 error, -2 timeout.
int sendAll(SOCKET s, const char* buf, size_t len, int timeoutMs);

// Receive exactly `len` bytes. n=len ok; 0 = orderly shutdown before any
// byte; -1 error; -2 timeout.
int recvExact(SOCKET s, char* buf, size_t len, int timeoutMs);

// Receive up to bufLen bytes (single call, non-blocking semantics via select).
int recvSome(SOCKET s, char* buf, size_t bufLen, int timeoutMs);

// TCP keepalive: idle 60s, interval 5s, 5 probes.
bool enableKeepalive(SOCKET s);

// Abortive close (RST) for the next closesocket.
void enableAbortiveClose(SOCKET s);

std::string wsaErrorMessage(int wsaError);
inline std::string lastError() { return wsaErrorMessage(WSAGetLastError()); }

// sockaddr_in helper from host-order endpoint.
sockaddr_in toSockaddr(const Endpoint4& ep);

}  // namespace aps::net
