// Time helpers (steady clocks for timeouts, wall clock for logs).
#pragma once

#include <cstdint>
#include <string>

namespace aps {

// Milliseconds since process-independent epoch (used for TTL bookkeeping).
int64_t nowMs();
int64_t steadyMs();

// "YYYY-MM-DD HH:MM:SS.mmm" in local time.
std::string formatLocalTime(int64_t unixMs);
// "YYYYMMDD-HHMMSS" in local time (for backup file names).
std::string fileTimestamp();

}  // namespace aps
