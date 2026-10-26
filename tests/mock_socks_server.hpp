// Scriptable local SOCKS5 server for tests. Behaves like a real proxy:
// performs the handshake, then actually connects to the requested target and
// pumps bytes. Failure modes can be injected per-test.
#pragma once

#ifndef APS_BUILD_TESTS
#error "test-only header"
#endif

#include <winsock2.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "aps/net.hpp"

namespace aps::test {

enum class MockSocksBehavior {
    Normal,          // full working proxy
    FailGreeting,    // send garbage after connect
    NoAcceptable,    // reply 05 FF
    FailAuth,        // require auth, then reject
    ResetAuthReply,  // require auth, then reset without a protocol reply
    RefuseConnect,   // reply rep != 0
    AcceptConnect,   // reply success without dialing a target; hold the tunnel
    EchoConnect,     // acknowledge and echo bytes; no upstream network/DNS
    Silence,         // never reply (drives client timeouts)
    CloseAfterData,  // CONNECT accepted, then EOF with no response bytes
};

struct MockSocksRequest {
    uint32_t dstIp = 0;      // host order
    std::string dstDomain;
    uint8_t addressType = 0;
    uint16_t dstPort = 0;
    std::string username;
    std::string password;
    bool usedAuth = false;
};

class MockSocks5Server {
public:
    ~MockSocks5Server() { stop(); }

    void setBehavior(MockSocksBehavior b) { behavior_ = b; }
    // DOMAIN requests never use system DNS in tests. Only explicit loopback
    // mappings may be dialed in Normal mode (configure before start).
    void setDomainTarget(const std::string& name, net::Endpoint4 target) {
        if (target.ip == 0x7F000001) domainTargets_[name] = target;
    }
    void setRequireAuth(bool r, std::string user = "", std::string pass = "") {
        requireAuth_ = r;
        authUser_ = std::move(user);
        authPass_ = std::move(pass);
    }

    bool start(uint16_t port = 0, bool dualStack = false) {
        listener_ = dualStack ? socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) : net::makeTcpSocket();
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = htonl(0x7F000001);  // 127.0.0.1
        sa.sin_port = htons(port);
        sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(port);
        DWORD v6only = 0;
        if (dualStack) setsockopt(listener_, IPPROTO_IPV6, IPV6_V6ONLY,
                                  reinterpret_cast<const char*>(&v6only), sizeof(v6only));
        if (bind(listener_, dualStack ? reinterpret_cast<sockaddr*>(&sa6) : reinterpret_cast<sockaddr*>(&sa),
                 dualStack ? sizeof(sa6) : sizeof(sa)) == SOCKET_ERROR ||
            listen(listener_, SOMAXCONN) == SOCKET_ERROR) {
            net::closeSocket(listener_);
            return false;
        }
        sockaddr_storage actual{};
        int len = sizeof(actual);
        getsockname(listener_, reinterpret_cast<sockaddr*>(&actual), &len);
        port_ = ntohs(reinterpret_cast<sockaddr_in*>(&actual)->sin_port);
        stopping_ = false;
        thread_ = std::thread([this] { loop(); });
        return true;
    }

    void stop() {
        stopping_ = true;
        if (listener_ != INVALID_SOCKET) {
            shutdown(listener_, SD_BOTH);
            closesocket(listener_);
            listener_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
        std::vector<SOCKET> pending;
        std::vector<std::thread> threads;
        {
            std::lock_guard<std::mutex> lk(mu_);
            pending = openSockets_;
            openSockets_.clear();
            threads.swap(clientThreads_);
        }
        for (SOCKET s : pending) {
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
        for (auto& t : threads) if (t.joinable()) t.join();
    }

    uint16_t port() const { return port_; }
    net::Endpoint4 endpoint() const { return net::Endpoint4{0x7F000001, port_}; }
    // Lets wire-level tests read only after the server has closed its socket.
    size_t completedConnectionCount() const { return completedConnections_.load(); }

    size_t requestCount() {
        std::lock_guard<std::mutex> lk(mu_);
        return requests_.size();
    }
    MockSocksRequest request(size_t i) {
        std::lock_guard<std::mutex> lk(mu_);
        return requests_.at(i);
    }

private:
    void track(SOCKET s) {
        std::lock_guard<std::mutex> lk(mu_);
        openSockets_.push_back(s);
    }
    void untrack(SOCKET s) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = openSockets_.begin(); it != openSockets_.end(); ++it) {
            if (*it == s) { openSockets_.erase(it); break; }
        }
    }

    void loop() {
        while (!stopping_) {
            sockaddr_storage peer{};
            int plen = sizeof(peer);
            SOCKET c = accept(listener_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) break;
            track(c);
            std::thread t([this, c] {
                serve(c);
                ++completedConnections_;
            });
            std::lock_guard<std::mutex> lk(mu_);
            clientThreads_.push_back(std::move(t));
        }
    }

    void serve(SOCKET c) {
        auto bail = [&](bool rst) {
            if (rst) net::enableAbortiveClose(c);
            untrack(c);
            net::closeSocket(c);
        };
        if (behavior_ == MockSocksBehavior::Silence) {
            char tmp[64];
            // Consume greeting, never answer.
            ::recv(c, tmp, sizeof(tmp), 0);
            Sleep(10000);
            bail(true);
            return;
        }
        // --- method negotiation (server side) --------------------------------
        unsigned char head[2];
        if (net::recvExact(c, reinterpret_cast<char*>(head), 2, 5000) != 2) return bail(false);
        if (head[0] != 0x05) {
            unsigned char junk[2] = {0x00, 0x00};
            net::sendAll(c, reinterpret_cast<char*>(junk), 2, 1000);  // FailGreeting-ish
            return bail(false);
        }
        int nmethods = head[1];
        unsigned char methods[16];
        if (nmethods > 0 &&
            net::recvExact(c, reinterpret_cast<char*>(methods), nmethods, 5000) != nmethods) {
            return bail(false);
        }
        if (behavior_ == MockSocksBehavior::FailGreeting) {
            unsigned char junk[2] = {0x99, 0x99};
            net::sendAll(c, reinterpret_cast<char*>(junk), 2, 1000);
            return bail(false);
        }
        if (behavior_ == MockSocksBehavior::NoAcceptable) {
            unsigned char r[2] = {0x05, 0xFF};
            net::sendAll(c, reinterpret_cast<char*>(r), 2, 1000);
            return bail(false);
        }
        bool clientOfferedAuth = false;
        for (int i = 0; i < nmethods; ++i) {
            if (methods[i] == 0x02) clientOfferedAuth = true;
        }
        if (requireAuth_ || behavior_ == MockSocksBehavior::FailAuth ||
            behavior_ == MockSocksBehavior::ResetAuthReply) {
            if (!clientOfferedAuth) {
                unsigned char r[2] = {0x05, 0xFF};
                net::sendAll(c, reinterpret_cast<char*>(r), 2, 1000);
                return bail(false);
            }
            unsigned char r[2] = {0x05, 0x02};
            net::sendAll(c, reinterpret_cast<char*>(r), 2, 1000);
            unsigned char uh[2];
            if (net::recvExact(c, reinterpret_cast<char*>(uh), 2, 5000) != 2) return bail(false);
            std::string user(uh[1], '\0'), pass(0, '\0');
            if (uh[1] && net::recvExact(c, user.data(), uh[1], 5000) != uh[1]) return bail(false);
            unsigned char pl;
            if (net::recvExact(c, reinterpret_cast<char*>(&pl), 1, 5000) != 1) return bail(false);
            pass.resize(pl);
            if (pl && net::recvExact(c, pass.data(), pl, 5000) != pl) return bail(false);
            if (behavior_ == MockSocksBehavior::ResetAuthReply) return bail(true);
            bool authOk = (behavior_ != MockSocksBehavior::FailAuth) &&
                          user == authUser_ && pass == authPass_;
            unsigned char ar[2] = {0x01, static_cast<unsigned char>(authOk ? 0x00 : 0x01)};
            net::sendAll(c, reinterpret_cast<char*>(ar), 2, 1000);
            // Keep the rejection queued for the client. An abortive close
            // can discard it and turn a credential failure into a reset.
            if (!authOk) return bail(false);
            lastUser_ = user;  // recorded below with the request
            pendingUser_ = user;
            pendingPass_ = pass;
        } else {
            unsigned char r[2] = {0x05, 0x00};
            net::sendAll(c, reinterpret_cast<char*>(r), 2, 1000);
        }
        // --- CONNECT ----------------------------------------------------------
        unsigned char req[4];
        if (net::recvExact(c, reinterpret_cast<char*>(req), 4, 5000) != 4) return bail(false);
        if (req[1] != 0x01) return bail(true);
        uint32_t dstIpNet = 0;
        uint16_t dstPortNet = 0;
        std::string dstDomain;
        if (req[3] == 0x01) {
            if (net::recvExact(c, reinterpret_cast<char*>(&dstIpNet), 4, 5000) != 4) return bail(false);
            if (net::recvExact(c, reinterpret_cast<char*>(&dstPortNet), 2, 5000) != 2) return bail(false);
        } else if (req[3] == 0x03) {
            unsigned char len = 0;
            if (net::recvExact(c, reinterpret_cast<char*>(&len), 1, 5000) != 1 || len == 0) return bail(false);
            dstDomain.resize(len);
            if (net::recvExact(c, dstDomain.data(), len, 5000) != len) return bail(false);
            if (net::recvExact(c, reinterpret_cast<char*>(&dstPortNet), 2, 5000) != 2) return bail(false);
        } else {
            return bail(true);
        }
        MockSocksRequest rq;
        rq.dstIp = ntohl(dstIpNet);
        rq.dstDomain = dstDomain;
        rq.addressType = req[3];
        rq.dstPort = ntohs(dstPortNet);
        rq.usedAuth = requireAuth_ || behavior_ == MockSocksBehavior::FailAuth;
        rq.username = pendingUser_;
        rq.password = pendingPass_;
        {
            std::lock_guard<std::mutex> lk(mu_);
            requests_.push_back(rq);
        }

        if (behavior_ == MockSocksBehavior::RefuseConnect) {
            unsigned char rep[10] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            net::sendAll(c, reinterpret_cast<char*>(rep), 10, 1000);
            // Graceful close, NOT abortive: an RST right after the reply can
            // race ahead of the data on loopback and discard it, so the
            // client would see a reset instead of the reply code (flaky
            // "connect_refused_reported" under ctest load).
            return bail(false);
        }
        if (behavior_ == MockSocksBehavior::AcceptConnect ||
            behavior_ == MockSocksBehavior::EchoConnect ||
            behavior_ == MockSocksBehavior::CloseAfterData) {
            // A deterministic tunnel for relay pump tests: acknowledge the
            // CONNECT without touching the network, then wait until the
            // relay closes its proxy-side socket.
            unsigned char rep[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            net::sendAll(c, reinterpret_cast<char*>(rep), 10, 1000);
            char buf[256];
            while (!stopping_) {
                int n = net::recvSome(c, buf, sizeof(buf), 200);
                if (n == -2) continue;
                if (n <= 0) break;
                if (behavior_ == MockSocksBehavior::CloseAfterData) {
                    Sleep(50);  // allow an application's earlier FIN to be observed
                    break;
                }
                if (behavior_ == MockSocksBehavior::EchoConnect &&
                    net::sendAll(c, buf, static_cast<size_t>(n), 2000) != 0) break;
            }
            return bail(false);
        }

        // Connect to the real target and splice.
        net::Endpoint4 target{rq.dstIp, rq.dstPort};
        if (!rq.dstDomain.empty()) {
            const auto it = domainTargets_.find(rq.dstDomain);
            if (it == domainTargets_.end()) return bail(false);
            target = it->second;
        }
        SOCKET t = net::makeTcpSocket();
        if (net::connectWithTimeout(t, target, 3000, nullptr) != 0) {
            unsigned char rep[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};  // host unreachable
            net::sendAll(c, reinterpret_cast<char*>(rep), 10, 1000);
            net::closeSocket(t);
            return bail(false);  // graceful: same RST-vs-reply race as RefuseConnect
        }
        unsigned char rep[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        net::sendAll(c, reinterpret_cast<char*>(rep), 10, 1000);

        char buf[16384];
        bool halfA = false, halfB = false;
        while (!stopping_) {
            fd_set r;
            FD_ZERO(&r);
            if (!halfA) FD_SET(c, &r);
            if (!halfB) FD_SET(t, &r);
            timeval tv{0, 200000};
            int n = select(0, &r, nullptr, nullptr, &tv);
            if (n < 0) break;
            if (n == 0) continue;
            if (FD_ISSET(c, &r)) {
                int r1 = ::recv(c, buf, sizeof(buf), 0);
                if (r1 == 0) { halfA = true; shutdown(t, SD_SEND); }
                else if (r1 < 0) break;
                else if (net::sendAll(t, buf, static_cast<size_t>(r1), 5000) != 0) break;
            }
            if (FD_ISSET(t, &r)) {
                int r2 = ::recv(t, buf, sizeof(buf), 0);
                if (r2 == 0) { halfB = true; shutdown(c, SD_SEND); }
                else if (r2 < 0) break;
                else if (net::sendAll(c, buf, static_cast<size_t>(r2), 5000) != 0) break;
            }
            if (halfA && halfB) break;
        }
        net::closeSocket(t);
        bail(false);
    }

    SOCKET listener_ = INVALID_SOCKET;
    std::thread thread_;
    std::vector<std::thread> clientThreads_;
    std::atomic<bool> stopping_{false};
    std::atomic<size_t> completedConnections_{0};
    uint16_t port_ = 0;
    MockSocksBehavior behavior_ = MockSocksBehavior::Normal;
    bool requireAuth_ = false;
    std::string authUser_, authPass_, lastUser_, pendingUser_, pendingPass_;
    mutable std::mutex mu_;
    std::vector<MockSocksRequest> requests_;
    std::map<std::string, net::Endpoint4> domainTargets_;
    std::vector<SOCKET> openSockets_;
};

}  // namespace aps::test
