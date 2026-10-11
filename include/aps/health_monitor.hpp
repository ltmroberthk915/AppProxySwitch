// Periodic SOCKS5 reachability probe with debouncing (2 fails -> down,
// 3 successes -> up again). Pushes state transitions to the engine.
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "aps/net.hpp"

namespace aps {

class HealthMonitor {
public:
    struct Params {
        net::Endpoint4 proxy;
        std::string username;   // optional SOCKS5 auth for the CONNECT probe
        std::string password;
        // Real-tunnel probe target: health = greeting + a CONNECT to this
        // endpoint THROUGH the tunnel. A kernel whose listener is up but
        // whose outbound is dead (the CFW false-healthy case: controller
        // /delay keeps reporting fine while SOCKS CONNECTs get RST'd) must
        // be detected — a bare TCP connect to the proxy port cannot.
        net::Endpoint4 dst{0x01010101, 443};  // 1.1.1.1:443 (host order)
        int intervalS = 10;
        int timeoutMs = 3000;
        int failThreshold = 2;
        int okThreshold = 3;
    };

    using StateCb = std::function<void(bool healthy, const std::string& detail)>;

    void start(const Params& params, StateCb onState);
    void stop();
    void updateParams(const Params& params);

    bool healthy() const { return healthy_.load(); }
    int lastLatencyMs() const { return lastLatencyMs_.load(); }

private:
    void loop();

    std::atomic<bool> stopping_{false};
    std::thread thread_;
    std::mutex paramsMu_;
    Params params_;
    std::atomic<bool> healthy_{true};
    std::atomic<int> lastLatencyMs_{-1};
    StateCb onState_;
};

}  // namespace aps
