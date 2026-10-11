#include "aps/stats.hpp"

namespace aps {

std::shared_ptr<RuleStats> StatsRegistry::get(const std::string& ruleId) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& p = map_[ruleId];
    if (!p) p = std::make_shared<RuleStats>();
    return p;
}

void StatsRegistry::connOpened(const std::string& ruleId, uint32_t pid) {
    auto s = get(ruleId);
    s->activeConns.fetch_add(1);
    s->totalConns.fetch_add(1);
    s->lastPid.store(pid);
}

void StatsRegistry::connClosed(const std::string& ruleId) {
    std::shared_ptr<RuleStats> s;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(ruleId);
        if (it != map_.end()) s = it->second;
    }
    if (s) s->activeConns.fetch_sub(1);
}

void StatsRegistry::connFailed(const std::string& ruleId, const std::string& err,
                               int64_t nowMs) {
    get(ruleId)->noteError(err, nowMs);
}

void StatsRegistry::connBlocked(const std::string& ruleId) {
    get(ruleId)->blockedConns.fetch_add(1);
}

json::Value StatsRegistry::rulesJson() const {
    json::Value arr = json::Value::makeArray();
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& kv : map_) {
        json::Value j = json::Value::makeObject();
        j.set("id", kv.first);
        j.set("conns", kv.second->activeConns.load());
        j.set("total", kv.second->totalConns.load());
        j.set("blocked", kv.second->blockedConns.load());
        j.set("bytes_up", kv.second->bytesUp.load());
        j.set("bytes_down", kv.second->bytesDown.load());
        j.set("last_pid", kv.second->lastPid.load());
        std::string err;
        {
            std::lock_guard<std::mutex> elk(kv.second->errMu);
            err = kv.second->lastError;
        }
        j.set("last_error", err);
        arr.append(std::move(j));
    }
    return arr;
}

}  // namespace aps
