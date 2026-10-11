// Config profile export/import (portable across machines).
//
// Export = the full config JSON with every DPAPI-encrypted field REMOVED
// (proxy.password_enc, proxy.clash_api.secret_enc, outlets[].password_enc,
// outlets[].clash_api.secret_enc) — the file never contains ciphertext and
// never contains plaintext secrets either.
//
// Import = overall replace (the user's chosen semantics), with one
// carve-out: any secret field that is absent or empty in the file keeps the
// LOCAL value (matched per-outlet by id). routing.autoOutletId is cleared —
// activation is machine-local; on the target machine the kernels get
// re-discovered and the user picks again.
#pragma once

#include <string>
#include <vector>

#include "aps/config.hpp"

namespace aps {

std::string exportProfileJson(const Config& cfg);

// On failure returns false and fills `error`; `out` is untouched then.
bool importProfileJson(const std::string& text, const Config& current, Config& out,
                       std::string* error, std::vector<std::string>* warnings = nullptr);

// Plain (non-atomic) write of an exported profile; returns false + error on
// any failure. Atomicity is not required: this file is a user-chosen export,
// not the live config.
bool saveProfileFile(const std::wstring& path, const Config& cfg, std::string* error);

// Read a profile file (1 MiB cap, matches the JSON parser's limit).
bool loadProfileFile(const std::wstring& path, std::string& text, std::string* error);

}  // namespace aps
