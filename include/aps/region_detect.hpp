// Node-name region detection for the region preference feature (multi-signal
// scan + priority arbitration + conservative unknowns). Different airports /
// proxy software name nodes differently, so the detector layers several
// signals: emoji flag pairs > IATA airport codes > city names > country
// names > ISO 2-letter tokens / English names > single Chinese characters.
// Same-priority conflicts (two regions from equally strong signals) return ""
// (unknown) instead of guessing.
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace aps::region {

// Returns a two-letter code ("HK","TW","SG","JP","US","KR","MO","UK","DE",
// "AU","CA","FR","RU","IN","TH","MY", ...), or "" when unknown.
std::string detectNodeRegion(std::string_view nodeName);

// wanted empty ("不限") matches everything.
bool matches(std::string_view detected, std::string_view wanted);
// Multi-select variant: empty set = 不限; true when `detected` equals any
// member of `wanted`.
bool matchesAny(std::string_view detected,
                const std::vector<std::string>& wanted);

}  // namespace aps::region
