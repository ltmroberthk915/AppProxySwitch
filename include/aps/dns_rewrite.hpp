// DNS query/response parsing and crafting for the anti-pollution filter.
// Handles the minimal subset we rewrite: one-question IN A/AAAA queries.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aps::dns {

// Parsed standard, single-question IN query. `type` is the wire QTYPE
// (1=A, 28=AAAA). Keeping this generic lets the cleanup layer answer AAAA
// with NOERROR/NODATA, forcing the application onto its cleaned IPv4 answer.
struct Query {
    uint16_t id = 0;
    uint16_t type = 0;
    bool recursionDesired = false;
    std::string name;
};

std::optional<Query> parseQuery(const uint8_t* pkt, size_t len);

// Parsed question of an A query; returns nullopt when it is not a plain
// single-question A query we can safely rewrite.
struct AQuery {
    uint16_t id;                    // transaction id (echo in the reply)
    std::string name;               // dot form, e.g. "chatgpt.com"
};

std::optional<AQuery> parseAQuery(const uint8_t* pkt, size_t len);

// Extracts every A record (host order) from a DNS response message (no
// TCP length prefix). Handles name compression pointers. Pure.
std::vector<uint32_t> parseARecords(const uint8_t* pkt, size_t len);

// Strict native-response association for TLS forwarding. Only addresses
// belonging to the question's answer/CNAME chain are accepted; unrelated
// authority/additional records must not authorize a different TLS name.
struct AResponse {
    uint16_t id = 0;
    std::string name;
    std::vector<uint32_t> ips;
    uint32_t ttl = 0;
};
std::optional<AResponse> parseAResponse(const uint8_t* pkt, size_t len);

// Builds a DNS response for `q` with `ips` as A-record answers. Returns the
// length written to `out` (0 when the packet would not fit).
size_t buildAResponse(const AQuery& q, const std::vector<uint32_t>& ipsHost,
                      uint8_t* out, size_t cap);

// Builds a successful response containing the original question and no
// answers (NOERROR/NODATA). Used for AAAA while IPv6 proxying is deliberately
// disabled for rule processes. Returns 0 when the packet would not fit.
size_t buildNoDataResponse(const Query& q, uint8_t* out, size_t cap);

// The engine's cleaned-DNS cache: name -> (A-record IPs, absolute expiry ms).
using DnsCache = std::map<std::string, std::pair<std::vector<uint32_t>, int64_t>>;

// Same grace used when a resolver outage serves a previous DNS answer.
constexpr int64_t kStaleGraceMs = 24 * 60 * 60 * 1000;
// Correlates a ClientHello name with the address APS returned for that name.
// This proves the naming association, NOT that the address is unpolluted.
// Unlike reverseLookup, shared/poisoned IPs never pick an arbitrary name.
bool nameHasAddress(const DnsCache& cache, const std::string& name,
                    uint32_t ipHost, int64_t nowMs);

// Reverse lookup over the cleaned-DNS cache (linear scan; the cache is small
// and this runs at most once per second for the connections view). Returns
// the name when `ipHost` is among the UNEXPIRED answers of some entry.
std::optional<std::string> reverseLookup(const DnsCache& cache, uint32_t ipHost,
                                         int64_t nowMs);

}  // namespace aps::dns
