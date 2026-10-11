#pragma once
#include "aps/json.hpp"
#include "aps/kernel_discovery.hpp"

namespace aps {
struct VergeSubscriptionTicket {
    std::string pipe, requestId;
    uint32_t clientPid = 0;
    json::Value identity;
    bool submitted = false;
};
enum class VergeRefreshState { Running, Succeeded, Failed, Unconfirmed };

// Pure validation helpers are also used by hermetic protocol tests.
bool validateVergeBridgeInfo(const json::Value& info, const DiscoveredKernel& kernel,
                            uint32_t serverPid, json::Value& identity);
VergeRefreshState validateVergeRefreshReply(const json::Value& reply,
    const std::string& requestId, std::string& error);
bool prepareVergeSubscription(const DiscoveredKernel& kernel,
                             VergeSubscriptionTicket& ticket, std::string& error);
VergeRefreshState advanceVergeSubscription(VergeSubscriptionTicket& ticket,
                                           std::string& error);
std::string vergeRefreshExplanation(const std::string& code);
}
