#include "aps/net.hpp"

#include <mstcpip.h>

#include <mutex>

namespace aps::net {

namespace {
std::once_flag g_wsastartup;
}

bool initWinsock() {
    bool ok = true;
    std::call_once(g_wsastartup, [&] {
        WSADATA wsa;
        ok = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    });
    return ok;
}

void cleanupWinsock() {
    // Intentionally not calling WSACleanup: every process here keeps Winsock
    // alive until exit; per-thread cleanup is not worth the ordering hazards.
}

SOCKET makeTcpSocket() {
    return WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                      WSA_FLAG_OVERLAPPED);
}

void closeSocket(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

int connectWithTimeout(SOCKET s, const Endpoint4& dst, int timeoutMs, std::string* err) {
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in sa = toSockaddr(dst);
    int rc = ::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    if (rc == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK) {
            if (err) *err = wsaErrorMessage(e);
            nb = 0;
            ioctlsocket(s, FIONBIO, &nb);
            return -1;
        }
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(s, &wset);
        FD_SET(s, &eset);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        int n = select(0, nullptr, &wset, &eset, &tv);
        if (n <= 0) {
            if (err) *err = "timed out";
            nb = 0;
            ioctlsocket(s, FIONBIO, &nb);
            return n == 0 ? -2 : -1;
        }
        if (FD_ISSET(s, &eset) && !FD_ISSET(s, &wset)) {
            int soerr = 0;
            int len = sizeof(soerr);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len);
            if (err) *err = wsaErrorMessage(soerr);
            nb = 0;
            ioctlsocket(s, FIONBIO, &nb);
            return -1;
        }
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return 0;
}

int sendAll(SOCKET s, const char* buf, size_t len, int timeoutMs) {
    size_t sent = 0;
    while (sent < len) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(s, &wset);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        int n = select(0, nullptr, &wset, nullptr, &tv);
        if (n == 0) return -2;
        if (n < 0) return -1;
        int w = ::send(s, buf + sent, static_cast<int>(len - sent), 0);
        if (w == SOCKET_ERROR) return -1;
        sent += static_cast<size_t>(w);
    }
    return 0;
}

int recvExact(SOCKET s, char* buf, size_t len, int timeoutMs) {
    size_t got = 0;
    while (got < len) {
        int n = recvSome(s, buf + got, len - got, timeoutMs);
        if (n == 0) return 0;      // orderly shutdown (only valid if got==0)
        if (n < 0) return n;
        got += static_cast<size_t>(n);
    }
    return static_cast<int>(len);
}

int recvSome(SOCKET s, char* buf, size_t bufLen, int timeoutMs) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    int n = select(0, &rset, nullptr, nullptr, &tv);
    if (n == 0) return -2;
    if (n < 0) return -1;
    int r = ::recv(s, buf, static_cast<int>(bufLen), 0);
    if (r == SOCKET_ERROR) return -1;
    return r;  // 0 = orderly shutdown
}

bool enableKeepalive(SOCKET s) {
    struct {
        unsigned long onoff;
        unsigned long keepalivetime;
        unsigned long keepaliveinterval;
    } ka{1, 60000, 5000};
    DWORD bytes = 0;
    return WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes,
                    nullptr, nullptr) == 0;
}

void enableAbortiveClose(SOCKET s) {
    linger lg{1, 0};
    setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
}

std::string wsaErrorMessage(int wsaError) {
    switch (wsaError) {
        case WSAECONNREFUSED: return "connection refused";
        case WSAETIMEDOUT: return "connection timed out";
        case WSAECONNRESET: return "connection reset";
        case WSAECONNABORTED: return "connection aborted";
        case WSAENETUNREACH: return "network unreachable";
        case WSAEHOSTUNREACH: return "host unreachable";
        case WSAENETDOWN: return "network down";
        case WSAEADDRINUSE: return "address in use";
        case WSAENOTSOCK: return "not a socket";
        case WSAEWOULDBLOCK: return "operation would block";
        case WSAESHUTDOWN: return "socket shut down";
        default: return "wsa error " + std::to_string(wsaError);
    }
}

sockaddr_in toSockaddr(const Endpoint4& ep) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.S_un.S_addr = htonl(ep.ip);
    sa.sin_port = htons(ep.port);
    return sa;
}

}  // namespace aps::net
