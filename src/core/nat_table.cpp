#include "aps/nat_table.hpp"

namespace aps {

std::shared_ptr<NatEntry> NatTable::create(uint32_t appIp, uint16_t appPort, uint32_t dstIp,
                                           uint16_t dstPort, const std::string& ruleId,
                                           const std::string& outletId, uint32_t pid,
                                           int64_t nowMs, bool dnsBridge) {
    auto entry = std::make_shared<NatEntry>();
    entry->appIp = appIp;
    entry->appPort = appPort;
    entry->origDstIp = dstIp;
    entry->origDstPort = dstPort;
    entry->ruleId = ruleId;
    entry->outletId = outletId;
    entry->pid = pid;
    entry->dnsBridge = dnsBridge;
    entry->tCreateMs.store(nowMs);
    entry->tLastActivityMs.store(nowMs);
    std::unique_lock<std::shared_mutex> lk(mu_);
    byRev_[RevKey{appIp, appPort}] = entry;  // displaces a stale entry, if any
    return entry;
}

std::shared_ptr<NatEntry> NatTable::findByFwd(uint32_t appIp, uint16_t appPort, uint32_t dstIp,
                                              uint16_t dstPort) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = byRev_.find(RevKey{appIp, appPort});
    if (it == byRev_.end()) return nullptr;
    const auto& e = it->second;
    if (e->origDstIp == dstIp && e->origDstPort == dstPort) return e;
    return nullptr;
}

std::shared_ptr<NatEntry> NatTable::findByRev(uint32_t appIp, uint16_t appPort) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = byRev_.find(RevKey{appIp, appPort});
    return it == byRev_.end() ? nullptr : it->second;
}

std::shared_ptr<NatEntry> NatTable::findByPort(uint16_t appPort) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    for (const auto& kv : byRev_) {
        if (kv.first.port == appPort) return kv.second;
    }
    return nullptr;
}

std::shared_ptr<NatEntry> NatTable::remove(uint32_t appIp, uint16_t appPort) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = byRev_.find(RevKey{appIp, appPort});
    if (it == byRev_.end()) return nullptr;
    auto entry = it->second;
    byRev_.erase(it);
    return entry;
}

std::vector<std::shared_ptr<NatEntry>> NatTable::snapshot() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<std::shared_ptr<NatEntry>> out;
    out.reserve(byRev_.size());
    for (const auto& kv : byRev_) out.push_back(kv.second);
    return out;
}

std::vector<std::shared_ptr<NatEntry>> NatTable::sweep(int64_t nowMs,
                                                       const NatSweepConfig& cfg) {
    std::vector<std::shared_ptr<NatEntry>> removed;
    std::unique_lock<std::shared_mutex> lk(mu_);
    for (auto it = byRev_.begin(); it != byRev_.end();) {
        const auto& e = it->second;
        NatState st = static_cast<NatState>(e->state.load());
        int64_t last = e->tLastActivityMs.load();
        bool dead = false;
        if (e->rstSeen.load()) {
            dead = nowMs - last >= cfg.rstGraceMs;
        } else if (st == NatState::SynSent) {
            dead = nowMs - e->tCreateMs.load() >= cfg.synTimeoutMs ||
                   e->relayClosed.load();
        } else if (st == NatState::Closing) {
            dead = nowMs - last >= cfg.finGraceMs;
        } else {
            dead = nowMs - last >= cfg.idleTimeoutMs || e->relayClosed.load();
        }
        if (dead) {
            removed.push_back(it->second);
            it = byRev_.erase(it);
        } else {
            ++it;
        }
    }
    return removed;
}

void NatTable::clear() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    byRev_.clear();
}

size_t NatTable::size() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return byRev_.size();
}

}  // namespace aps
