// Per-rule live statistics (active/total connections, byte counters, last
// error, last PID). Backs both the GUI table and the IPC STATS message.
#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "aps/json.hpp"

namespace aps {

struct RuleStats {
    std::atomic<uint64_t> activeConns{0};
    std::atomic<uint64_t> totalConns{0};
    std::atomic<uint64_t> bytesUp{0};
    std::atomic<uint64_t> bytesDown{0};
    // TCP SYNs dropped by a "block"-action rule. UDP/IPv6-SYN drops under
    // block rules are not counted here.
    std::atomic<uint64_t> blockedConns{0};
    std::atomic<uint32_t> lastPid{0};
    std::mutex errMu;
    std::string lastError;
    int64_t lastErrorTs = 0;

    void noteError(const std::string& msg, int64_t nowMs) {
        std::lock_guard<std::mutex> lk(errMu);
        lastError = msg.substr(0, 200);
        lastErrorTs = nowMs;
    }
};

class StatsRegistry {
public:
    std::shared_ptr<RuleStats> get(const std::string& ruleId);

    void connOpened(const std::string& ruleId, uint32_t pid);
    void connClosed(const std::string& ruleId);
    void connFailed(const std::string& ruleId, const std::string& err, int64_t nowMs);
    void connBlocked(const std::string& ruleId);

    // Serialized STATS payload section (without outer wrapper).
    json::Value rulesJson() const;

private:
    mutable std::mutex mu_;
    std::map<std::string, std::shared_ptr<RuleStats>> map_;
};

}  // namespace aps
