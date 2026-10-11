// Minimal Clash-family external-controller client (loopback TCP HTTP or
// local named pipe, with optional Bearer auth). Purpose: node health probing and automatic
// selector switching. Metadata-only: never touches traffic payloads.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "aps/net.hpp"

namespace aps {

struct ClashApiResult {
    bool ok = false;
    int httpStatus = 0;
    std::string body;
    std::string error;
};

// Availability samples retained by the Clash-family controller for one
// concrete proxy. A delay > 0 is a successful sample; zero is a recorded
// failure. Controllers that do not expose history simply leave samples=0.
struct ClashNodeHistory {
    int successes = 0;
    int samples = 0;
};

// One selector group as reported by GET /proxies.
struct ClashGroup {
    std::string name;
    std::string type;     // "Selector", "URLTest", ...
    std::string now;      // currently selected node (may be empty)
    std::vector<std::string> nodes;
    std::map<std::string, ClashNodeHistory> history;
};

class ClashApiClient {
public:
    // Nonempty pipe selects local pipe transport; pipePid pins its server
    // identity when known. TCP callers keep the original three arguments.
    ClashApiClient(std::string host, uint16_t port, std::string secret,
                   std::string pipe = {}, uint32_t pipePid = 0);

    // GET /version with a short timeout; used to discover/verify an API.
    bool probe(std::string* err, int timeoutMs = 3000);

    // Three-state probe: reachable / reachable-but-401 / unreachable.
    // Used by auto-detection so a secret-protected API is still FOUND.
    struct ProbeResult {
        bool reachable = false;
        bool needSecret = false;
        int httpStatus = 0;
    };
    ProbeResult probeAny(int timeoutMs = 1000);

    // GET /proxies with optional /configs and /rules runtime metadata.
    // Rule mode resolves selected nested selectors used by actual rules;
    // the returned `now` follows selected subgroups to the concrete node.
    // older controllers return the first Selector with a non-empty `now`
    // (the group the default egress is likely riding), plus any fallback
    // Selector group. When `all` is non-null it receives EVERY group with
    // its node list (used for group-membership class matching, e.g.
    // "GROUP:🤖AI服务").
    std::optional<ClashGroup> currentSelectorGroup(
        std::string* err, int timeoutMs = 3000,
        std::vector<ClashGroup>* all = nullptr,
        std::string* runtimeMode = nullptr);

    // GET /proxies/{node}/delay?url=...&timeout=...  -> latency ms;
    // -1 on timeout/failure (node dead).
    int nodeDelay(const std::string& node, const std::string& url,
                  int timeoutMs, int httpTimeoutMs);

    // PUT /proxies/{group} {"name": node}
    bool switchNode(const std::string& group, const std::string& node,
                    std::string* err);

    // GET /dns/query?name=...&type=A -> unpoisoned real IPv4 addresses.
    // Uses the kernel's own DNS (remote/filtered), bypassing local pollution.
    bool resolveA(const std::string& name, std::vector<uint32_t>& ipsHost,
                  std::string* err, int timeoutMs = 4000);

    // PUT /configs?force=true with a full YAML config — the standard
    // hot-reload endpoint used for subscription refreshes. Replaces the
    // kernel's running config WITHOUT a process restart.
    bool putConfigs(const std::string& yaml, std::string* err,
                    int timeoutMs = 15000);

    static std::string urlEncode(const std::string& s);

private:
    ClashApiResult request(const std::string& method, const std::string& path,
                           const std::string& body, int timeoutMs);

    std::string host_;
    uint16_t port_;
    std::string secret_;
    std::string pipe_;
    uint32_t pipePid_ = 0;
};

// Find the controller port for a specific proxy kernel. Discovery order:
//   1. ports held by the SAME process as `socksPort` (CFW: SOCKS 7890 and
//      its random API port always share one clash-win64 process) — this is
//      what distinguishes one kernel's API from another's;
//   2. every remaining LISTENING 127.0.0.1 / 0.0.0.0 port, ascending.
// No hard-coded port list: a real controller is whatever answers a Clash
// /version on the loopback. Returns 0 when none found; sets *needSecret
// when the API answered 401/403 (configured secret required or wrong).
uint16_t autoDetectClashApiPort(const std::string& host, const std::string& secret,
                                uint16_t socksPort, bool* needSecret = nullptr);

}  // namespace aps
