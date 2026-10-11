// NAT table: maps redirected flows both ways.
//   forward key  (appIp, appPort, origDstIp, origDstPort)  -> rewrite dst
//   reverse key  (appIp, appPort)                          -> rewrite src / relay lookup
// One (appIp, appPort) can only belong to one active TCP flow, which is what
// makes the two-tuple reverse key unambiguous.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "aps/net.hpp"
#include "aps/relay_server.hpp"

namespace aps {

enum class NatState { SynSent, Established, Closing };

struct NatEntry : public IRelaySessionSink {
    // Flow identity (all host byte order).
    uint32_t appIp = 0;
    uint16_t appPort = 0;
    uint32_t origDstIp = 0;
    uint16_t origDstPort = 0;
    std::string ruleId;
    std::string outletId;   // frozen at SYN time; "" = default outlet
    uint32_t pid = 0;
    // This flow is TCP DNS redirected to the relay's local clean-DNS bridge,
    // not a normal SOCKS session. The original destination is retained for
    // exact fail-open fallback.
    bool dnsBridge = false;

    std::atomic<int32_t> state{static_cast<int32_t>(NatState::SynSent)};
    std::atomic<bool> rstSeen{false};
    std::atomic<bool> appFin{false};
    std::atomic<bool> relayFin{false};
    std::atomic<bool> relayClosed{false};  // relay session finished

    // Next sequence number the app expects from origDst (for RST synthesis).
    std::atomic<uint32_t> nextSeqRelayToApp{0};
    std::atomic<bool> seqValid{false};

    std::atomic<uint64_t> bytesUp{0};
    std::atomic<uint64_t> bytesDown{0};

    std::atomic<int64_t> tCreateMs{0};
    std::atomic<int64_t> tLastActivityMs{0};

    // IRelaySessionSink
    void onBytes(uint64_t up, uint64_t down) override {
        bytesUp.fetch_add(up);
        bytesDown.fetch_add(down);
    }
    void onClosed() override { relayClosed.store(true); }
};

struct NatSweepConfig {
    int synTimeoutMs = 30000;
    int idleTimeoutMs = 86400 * 1000;
    int finGraceMs = 30000;
    int rstGraceMs = 2000;
};

class NatTable {
public:
    // Creates (or replaces) the entry for (appIp, appPort). Returns the
    // previous entry if one was displaced.
    std::shared_ptr<NatEntry> create(uint32_t appIp, uint16_t appPort, uint32_t dstIp,
                                     uint16_t dstPort, const std::string& ruleId,
                                     const std::string& outletId, uint32_t pid,
                                     int64_t nowMs, bool dnsBridge = false);

    std::shared_ptr<NatEntry> findByFwd(uint32_t appIp, uint16_t appPort, uint32_t dstIp,
                                        uint16_t dstPort);
    std::shared_ptr<NatEntry> findByRev(uint32_t appIp, uint16_t appPort);
    // Port-only fallback: the app port is unique among active flows (one
    // (ip,port) tuple = one flow, see RevKey). Loopback delivery of our
    // rewritten SYNs can rewrite the source IP to 127.0.0.1 (measured when
    // the kernels' TUN adapter is down) — the relay must still find the
    // entry, or every proxied flow dies the moment the TUN disappears.
    std::shared_ptr<NatEntry> findByPort(uint16_t appPort);

    std::shared_ptr<NatEntry> remove(uint32_t appIp, uint16_t appPort);

    // Snapshot of all entries (e.g., for teardown or stats).
    std::vector<std::shared_ptr<NatEntry>> snapshot() const;

    // Removes timed-out / finished entries; returns the removed entries so the
    // caller can adjust counters and log.
    std::vector<std::shared_ptr<NatEntry>> sweep(int64_t nowMs, const NatSweepConfig& cfg);

    // Drop everything (engine shutdown path).
    void clear();

    size_t size() const;

private:
    struct RevKey {
        uint32_t ip;
        uint16_t port;
        bool operator==(const RevKey& o) const { return ip == o.ip && port == o.port; }
    };
    struct RevKeyHash {
        size_t operator()(const RevKey& k) const {
            return std::hash<uint64_t>()((uint64_t)k.ip << 16 | k.port);
        }
    };
    mutable std::shared_mutex mu_;
    std::unordered_map<RevKey, std::shared_ptr<NatEntry>, RevKeyHash> byRev_;
};

}  // namespace aps
