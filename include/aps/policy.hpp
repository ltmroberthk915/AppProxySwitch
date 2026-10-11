// Centralized fail-open / fail-closed decision points.
#pragma once

#include <string>

#include "aps/config.hpp"

namespace aps {

enum class NewFlowDecision { Proxy, Direct, Drop };

inline NewFlowDecision decideNewFlow(bool engineEnabled, bool proxyHealthy,
                                     const std::string& failMode) {
    if (!engineEnabled) return NewFlowDecision::Direct;
    if (proxyHealthy) return NewFlowDecision::Proxy;
    // Proxy is down: fail-open lets rule traffic fall back to direct
    // (default); fail-closed blackholes NEW rule connections instead.
    return failMode == "closed" ? NewFlowDecision::Drop : NewFlowDecision::Direct;
}

}  // namespace aps
