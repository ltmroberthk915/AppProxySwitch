// Minimal local HTTP responder for tests (loopback only, no external net).
#pragma once

#ifndef APS_BUILD_TESTS
#error "test-only header"
#endif

#include <winsock2.h>

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "aps/net.hpp"

namespace aps::test {

class MockHttpServer {
public:
    ~MockHttpServer() { stop(); }

    void setResponse(std::string body) { body_ = std::move(body); }
    void setStatus(unsigned status, std::string headers = {}) {
        status_ = status; responseHeaders_ = std::move(headers);
    }
    void requireHeader(std::string header) { requiredHeader_ = std::move(header); }

    // bindIpHost: host-byte-order IPv4 to bind (e2e uses the LAN address so
    // the destination is not in 127/8 and thus visible to the filter).
    bool start(uint16_t port = 0, uint32_t bindIpHost = 0x7F000001) {
        listener_ = net::makeTcpSocket();
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = htonl(bindIpHost);
        sa.sin_port = htons(port);
        if (bind(listener_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR ||
            listen(listener_, SOMAXCONN) == SOCKET_ERROR) {
            net::closeSocket(listener_);
            return false;
        }
        sockaddr_in actual{};
        int len = sizeof(actual);
        getsockname(listener_, reinterpret_cast<sockaddr*>(&actual), &len);
        port_ = ntohs(actual.sin_port);
        boundIp_ = ntohl(actual.sin_addr.S_un.S_addr);
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
        std::vector<std::thread> threads;
        {
            std::lock_guard<std::mutex> lk(mu_);
            threads.swap(workers_);
        }
        for (auto& t : threads) if (t.joinable()) t.join();
    }

    uint16_t port() const { return port_; }
    // The address actually bound (useful for 0.0.0.0 + LAN access).
    uint32_t boundIp() const { return boundIp_; }

    struct Hit {
        std::string requestLine;
        std::string body;
    };
    size_t hits() {
        std::lock_guard<std::mutex> lk(mu_);
        return hits_.size();
    }
    Hit hit(size_t i) {
        std::lock_guard<std::mutex> lk(mu_);
        return hits_.at(i);
    }

private:
    void loop() {
        while (!stopping_) {
            sockaddr_in peer{};
            int plen = sizeof(peer);
            SOCKET c = accept(listener_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) break;
            lastPeerPort_ = ntohs(peer.sin_port);
            std::thread t([this, c] { serve(c); });
            std::lock_guard<std::mutex> lk(mu_);
            workers_.push_back(std::move(t));
        }
    }

    void serve(SOCKET c) {
        std::string req;
        char buf[4096];
        while (req.find("\r\n\r\n") == std::string::npos && req.size() < 65536) {
            int n = net::recvSome(c, buf, sizeof(buf), 5000);
            if (n <= 0) {
                net::closeSocket(c);
                return;
            }
            req.append(buf, static_cast<size_t>(n));
        }
        size_t lineEnd = req.find("\r\n");
        std::string requestLine = req.substr(0, lineEnd == std::string::npos ? req.size() : lineEnd);
        {
            std::lock_guard<std::mutex> lk(mu_);
            hits_.push_back(Hit{requestLine, req});
        }
        const unsigned status = requiredHeader_.empty() || req.find(requiredHeader_) != std::string::npos
                                    ? status_ : 403;
        std::string response = "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK\r\n" : " Test\r\n") + responseHeaders_ +
                               "Content-Type: text/plain\r\nContent-Length: " +
                               std::to_string(body_.size()) + "\r\nConnection: close\r\n\r\n" + body_;
        net::sendAll(c, response.data(), response.size(), 5000);
        shutdown(c, SD_SEND);
        // Wait for the client side to close so FIN semantics are exercised.
        while (net::recvSome(c, buf, sizeof(buf), 1000) > 0) {}
        net::closeSocket(c);
    }

    SOCKET listener_ = INVALID_SOCKET;
    std::thread thread_;
    std::vector<std::thread> workers_;
    std::atomic<bool> stopping_{false};
    uint16_t port_ = 0;
    uint32_t boundIp_ = 0;
    std::string body_ = "aps-mock-http-ok";
    unsigned status_ = 200;
    std::string responseHeaders_, requiredHeader_;
    std::atomic<uint16_t> lastPeerPort_{0};
    std::mutex mu_;
    std::vector<Hit> hits_;
};

}  // namespace aps::test
