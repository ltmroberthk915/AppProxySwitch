#pragma once

#include <cstdint>
#include <string>

namespace aps {
// Local HTTP-over-named-pipe transport. Never connects to a remote SMB pipe,
// never allows the server to impersonate the (possibly elevated) engine.
bool localControllerPipe(const std::string& name);
bool requestControllerPipe(const std::string& name, uint32_t expectedPid,
                           const std::string& request, int timeoutMs,
                           std::string& response, std::string& error);
// Same-account, newline-framed cooperation protocol. Validates the actual
// server PID on every connection; an ACK prevents dropping unread replies.
bool requestProfileBridgePipe(const std::string& name, uint32_t expectedPid,
                              const std::string& request, int timeoutMs,
                              uint32_t& ownerPid, std::string& response,
                              std::string& error);
}
