#include "aps/health_monitor.hpp"

#include <mutex>

#include "aps/socks5_client.hpp"

namespace aps {

void HealthMonitor::start(const Params& params, StateCb onState) {
    {
        std::lock_guard<std::mutex> lk(paramsMu_);
        params_ = params;
    }
    onState_ = std::move(onState);
    stopping_.store(false);
    thread_ = std::thread([this] { loop(); });
}

void HealthMonitor::stop() {
    stopping_.store(true);
    if (thread_.joinable()) thread_.join();
}

void HealthMonitor::updateParams(const Params& params) {
    std::lock_guard<std::mutex> lk(paramsMu_);
    params_ = params;
}

void HealthMonitor::loop() {
    int consecutiveFails = 0;
    int consecutiveOks = 0;
    bool announced = false;
    while (!stopping_.load()) {
        Params p;
        {
            std::lock_guard<std::mutex> lk(paramsMu_);
            p = params_;
        }
        int latency = -1;
        std::string err;
        bool ok = Socks5Client::probe(p.proxy, p.timeoutMs, &latency, &err,
                                      p.username, p.password);
        if (ok && p.dst.ip != 0 && p.dst.port != 0) {
            // Real CONNECT through the tunnel: catches kernels whose
            // listener is up but whose outbound is broken (measured: a
            // crashed CFW core kept answering greetings and controller
            // /delay while RST-ing every real CONNECT). The target is
            // auto-detected by the engine; {0,0} means "not resolved yet"
            // — degrade to the greeting-only probe.
            SOCKET s = INVALID_SOCKET;
            ok = Socks5Client::connect(p.proxy, p.username, p.password, p.dst,
                                       p.timeoutMs, s, &err);
            if (ok) {
                net::closeSocket(s);
            } else {
                err = "tunnel CONNECT failed: " + err;
            }
        }
        lastLatencyMs_.store(latency);

        if (ok) {
            consecutiveOks++;
            consecutiveFails = 0;
            if ((!healthy_.load() && consecutiveOks >= p.okThreshold) || !announced) {
                healthy_.store(true);
                announced = true;
                if (onState_) onState_(true,
                    std::string(p.dst.ip && p.dst.port ? "SOCKS5 CONNECT accepted" : "SOCKS5 greeting accepted") +
                    "; TLS/HTTP not checked; latency " + std::to_string(latency) + "ms");
            }
        } else {
            consecutiveFails++;
            consecutiveOks = 0;
            if ((healthy_.load() && consecutiveFails >= p.failThreshold) || !announced) {
                healthy_.store(false);
                announced = true;
                if (onState_) onState_(false, err.empty() ? "unreachable" : err);
            }
        }

        for (int i = 0; i < p.intervalS * 10 && !stopping_.load(); ++i) {
            Sleep(100);
        }
    }
}

}  // namespace aps
