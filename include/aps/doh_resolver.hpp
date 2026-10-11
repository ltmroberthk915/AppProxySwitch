// DNS-over-HTTPS resolver dialed through a local HTTP CONNECT proxy (a
// Clash kernel's mixed-port). First-principles anti-poisoning: plain
// TCP-53 answers can be swapped mid-flight wherever the return path
// crosses the GFW (measured repeatedly 2026-08-28..31: well-formed fake
// Facebook/Twitter IPs returned through transit nodes even when querying
// 8.8.8.8); an HTTPS body cannot be injected. The DoH endpoint set comes
// from the user's routing.dns_servers config — Google (8.8.8.8) and
// Cloudflare (1.1.1.1) serve the JSON API directly on their IPs with
// valid certificates, no bootstrap name needed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aps::doh {

// DoH GET: https://<serverIp>/resolve?name=<name>&type=A via the HTTP proxy
// listening on 127.0.0.1:proxyPort. WinHTTP sessions are reused per proxy
// port so bursts of browser lookups can reuse CONNECT/TLS connections.
// Collects type-A answer IPs (host order). Returns false + err on any failure
// (proxy dead, TLS rejected, non-JSON, DNS status != 0) — the caller falls
// back to the plain-53 path.
bool resolveViaHttpProxy(uint16_t proxyPort, uint32_t serverIp,
                         const std::string& name, std::vector<uint32_t>& ips,
                         int timeoutMs, std::string* err);

// Lifecycle hook: call only after DNS request threads have stopped. Closing
// the parent sessions also releases WinHTTP's pooled CONNECT/TLS connections.
void closeHttpProxySessions();

// Read-only cache introspection for the hermetic regression test.
size_t cachedHttpProxySessionCountForTest();

}  // namespace aps::doh
