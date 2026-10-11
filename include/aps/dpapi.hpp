// DPAPI wrappers for at-rest secrets (proxy password) + base64 helpers.
#pragma once

#include <string>
#include <string_view>

namespace aps::crypto {

// Encrypt with the current user's scope; returns base64 blob (empty on error).
std::string protectToBase64(std::string_view utf8Plain);

// Decrypt a base64 DPAPI blob; ok=false on any failure (never throws).
std::string unprotectFromBase64(std::string_view base64, bool* ok);

// True when the process token has the Administrators group enabled.
bool isProcessElevated();

}  // namespace aps::crypto
