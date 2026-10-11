#pragma once
#include <cstdint>

namespace aps {
// Observe both packet work and receive-thread wait progress. A pump stuck in
// packet handling stops both counters, even when no other packets arrive.
class PumpWatchdog {
public:
    explicit PumpWatchdog(int64_t now) : lastChangeMs_(now), lastObservationMs_(now) {}
    bool stalled(int64_t now, uint64_t packets, uint64_t waits,
                 bool active, bool exited) {
        // A paused timer (sleep/resume or scheduler starvation) cannot prove
        // that the pump failed during that unobserved interval. Re-arm it.
        if (!active || now - lastObservationMs_ > 10000 ||
            packets != packets_ || waits != waits_) {
            packets_ = packets;
            waits_ = waits;
            lastChangeMs_ = now;
        }
        lastObservationMs_ = now;
        return active && (exited || now - lastChangeMs_ > 120000);
    }
private:
    uint64_t packets_ = 0, waits_ = 0;
    int64_t lastChangeMs_;
    int64_t lastObservationMs_;
};
}  // namespace aps
