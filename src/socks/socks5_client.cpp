#include "aps/socks5_client.hpp"

#include <cstring>
#include <vector>

namespace aps {

using namespace aps::net;

namespace {

bool negotiate(SOCKET s, const std::string& username, const std::string& password,
               int timeoutMs, std::string* err,
               Socks5FailureKind* failureKind) {
    auto failAs = [failureKind](Socks5FailureKind kind) {
        if (failureKind) *failureKind = kind;
    };
    // Method selection: we prefer no-auth (0x00); offer user/pass (0x02) when
    // credentials are configured.
    const bool wantAuth = !username.empty();
    unsigned char greet[4];
    size_t greetLen = wantAuth ? 4 : 3;
    greet[0] = 0x05;
    greet[1] = static_cast<unsigned char>(wantAuth ? 2 : 1);
    greet[2] = 0x00;  // no authentication
    if (wantAuth) greet[3] = 0x02;  // username/password
    if (sendAll(s, reinterpret_cast<const char*>(greet), greetLen, timeoutMs) != 0) {
        if (err) *err = "SOCKS5: failed sending greeting: " + lastError();
        failAs(Socks5FailureKind::ProxyEndpoint);
        return false;
    }
    unsigned char reply[2];
    int n = recvExact(s, reinterpret_cast<char*>(reply), 2, timeoutMs);
    if (n != 2) {
        if (err) *err = n == -2 ? "SOCKS5: greeting reply timed out"
                                : "SOCKS5: failed reading greeting reply";
        failAs(Socks5FailureKind::ProxyEndpoint);
        return false;
    }
    if (reply[0] != 0x05) {
        if (err) *err = "SOCKS5: server replied wrong version";
        failAs(Socks5FailureKind::ProxyEndpoint);
        return false;
    }
    if (reply[1] == 0xFF) {
        if (err) *err = "SOCKS5: no acceptable auth method";
        failAs(Socks5FailureKind::Configuration);
        return false;
    }
    if (reply[1] == 0x00) return true;  // no auth
    if (reply[1] != 0x02) {
        if (err) *err = "SOCKS5: server chose unsupported auth method";
        failAs(Socks5FailureKind::Configuration);
        return false;
    }
    // RFC 1929 username/password subnegotiation.
    if (username.size() > 255 || password.size() > 255) {
        if (err) *err = "SOCKS5: username/password too long (max 255)";
        failAs(Socks5FailureKind::Configuration);
        return false;
    }
    unsigned char auth[3 + 255 + 255];
    size_t len = 0;
    auth[len++] = 0x01;
    auth[len++] = static_cast<unsigned char>(username.size());
    memcpy(auth + len, username.data(), username.size());
    len += username.size();
    auth[len++] = static_cast<unsigned char>(password.size());
    memcpy(auth + len, password.data(), password.size());
    len += password.size();
    if (sendAll(s, reinterpret_cast<const char*>(auth), len, timeoutMs) != 0) {
        if (err) *err = "SOCKS5: failed sending auth: " + lastError();
        failAs(Socks5FailureKind::ProxyEndpoint);
        return false;
    }
    unsigned char authReply[2];
    if (recvExact(s, reinterpret_cast<char*>(authReply), 2, timeoutMs) != 2) {
        if (err) *err = "SOCKS5: auth reply timed out or malformed";
        failAs(Socks5FailureKind::ProxyEndpoint);
        return false;
    }
    if (authReply[1] != 0x00) {
        if (err) *err = "SOCKS5: username/password rejected";
        failAs(Socks5FailureKind::Configuration);
        return false;
    }
    return true;
}

bool connectRequest(const net::Endpoint4& proxy, const std::string& username,
                    const std::string& password,
                    const std::vector<unsigned char>& req,
                    int timeoutMs, SOCKET& outSock, std::string* err,
                    Socks5FailureKind* failureKind) {
    outSock = INVALID_SOCKET;
    if (failureKind) *failureKind = Socks5FailureKind::None;
    SOCKET s = makeTcpSocket();
    if (s == INVALID_SOCKET) {
        if (err) *err = "SOCKS5: socket() failed: " + lastError();
        if (failureKind) *failureKind = Socks5FailureKind::Internal;
        return false;
    }
    int rc = connectWithTimeout(s, proxy, timeoutMs, err);
    if (rc != 0) {
        if (err && rc == -2) *err = "SOCKS5: proxy connect timed out";
        if (failureKind) *failureKind = Socks5FailureKind::ProxyEndpoint;
        closeSocket(s);
        return false;
    }
    if (!negotiate(s, username, password, timeoutMs, err, failureKind)) {
        closeSocket(s);
        return false;
    }
    if (sendAll(s, reinterpret_cast<const char*>(req.data()), req.size(), timeoutMs) != 0) {
        if (err) *err = "SOCKS5: failed sending CONNECT: " + lastError();
        if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
        closeSocket(s);
        return false;
    }
    unsigned char head[4];
    if (recvExact(s, reinterpret_cast<char*>(head), 4, timeoutMs) != 4) {
        if (err) *err = "SOCKS5: CONNECT reply timed out or malformed";
        if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
        closeSocket(s);
        return false;
    }
    if (head[0] != 0x05) {
        if (err) *err = "SOCKS5: CONNECT reply has wrong version";
        if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
        closeSocket(s);
        return false;
    }
    if (head[1] != 0x00) {
        if (err) *err = "SOCKS5: CONNECT failed, reply code " + std::to_string(head[1]);
        if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
        closeSocket(s);
        return false;
    }
    // Consume the bound address based on ATYP.
    size_t restLen = 0;
    switch (head[3]) {
        case 0x01: restLen = 4 + 2; break;               // IPv4
        case 0x03: {                                     // domain
            unsigned char dlen = 0;
            if (recvExact(s, reinterpret_cast<char*>(&dlen), 1, timeoutMs) != 1) {
                if (err) *err = "SOCKS5: truncated domain in CONNECT reply";
                if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
                closeSocket(s);
                return false;
            }
            restLen = dlen + 2;
            break;
        }
        case 0x04: restLen = 16 + 2; break;              // IPv6
        default:
            if (err) *err = "SOCKS5: bad ATYP in CONNECT reply";
            if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
            closeSocket(s);
            return false;
    }
    char skip[300];
    while (restLen > 0) {
        size_t chunk = restLen > sizeof(skip) ? sizeof(skip) : restLen;
        int n = recvExact(s, skip, chunk, timeoutMs);
        if (n <= 0) {
            if (err) *err = "SOCKS5: truncated CONNECT reply";
            if (failureKind) *failureKind = Socks5FailureKind::Tunnel;
            closeSocket(s);
            return false;
        }
        restLen -= chunk;
    }
    outSock = s;
    return true;
}

}  // namespace

bool Socks5Client::connect(const net::Endpoint4& proxy, const std::string& username,
                           const std::string& password, const net::Endpoint4& dst,
                           int timeoutMs, SOCKET& outSock, std::string* err,
                           Socks5FailureKind* failureKind) {
    std::vector<unsigned char> req{0x05, 0x01, 0x00, 0x01};
    const uint32_t beIp = htonl(dst.ip);
    const auto* ip = reinterpret_cast<const unsigned char*>(&beIp);
    req.insert(req.end(), ip, ip + 4);
    req.push_back(static_cast<unsigned char>(dst.port >> 8));
    req.push_back(static_cast<unsigned char>(dst.port & 0xFF));
    return connectRequest(proxy, username, password, req, timeoutMs, outSock,
                          err, failureKind);
}

bool Socks5Client::connectDomain(const net::Endpoint4& proxy,
                                 const std::string& username,
                                 const std::string& password,
                                 const std::string& hostname, uint16_t port,
                                 int timeoutMs, SOCKET& outSock, std::string* err,
                                 Socks5FailureKind* failureKind) {
    bool valid = !hostname.empty() && hostname.size() <= 255 && port != 0;
    for (unsigned char c : hostname) {
        if (c <= 32 || c >= 127 || c == '/' || c == '\\' || c == ':') valid = false;
    }
    if (!valid) {
        outSock = INVALID_SOCKET;
        if (err) *err = "SOCKS5: invalid domain destination";
        if (failureKind) *failureKind = Socks5FailureKind::Configuration;
        return false;
    }
    std::vector<unsigned char> req{0x05, 0x01, 0x00, 0x03,
                                   static_cast<unsigned char>(hostname.size())};
    req.insert(req.end(), hostname.begin(), hostname.end());
    req.push_back(static_cast<unsigned char>(port >> 8));
    req.push_back(static_cast<unsigned char>(port & 0xFF));
    return connectRequest(proxy, username, password, req, timeoutMs, outSock,
                          err, failureKind);
}

bool Socks5Client::probe(const net::Endpoint4& proxy, int timeoutMs, int* latencyMs,
                         std::string* err, const std::string& username,
                         const std::string& password) {
    if (latencyMs) *latencyMs = -1;
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceCounter(&t0);
    SOCKET s = makeTcpSocket();
    if (s == INVALID_SOCKET) {
        if (err) *err = "socket() failed: " + lastError();
        return false;
    }
    if (connectWithTimeout(s, proxy, timeoutMs, err) != 0) {
        closeSocket(s);
        return false;
    }
    if (!negotiate(s, username, password, timeoutMs, err, nullptr)) {
        closeSocket(s);
        return false;
    }
    QueryPerformanceCounter(&t1);
    QueryPerformanceFrequency(&freq);
    if (latencyMs) {
        *latencyMs = static_cast<int>((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
    }
    closeSocket(s);
    return true;
}

}  // namespace aps
