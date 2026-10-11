#include "aps/dpapi.hpp"

#include <windows.h>
#include <dpapi.h>

#include <vector>

#include "aps/string_util.hpp"

namespace aps::crypto {

std::string protectToBase64(std::string_view utf8Plain) {
    if (utf8Plain.empty()) return {};
    DATA_BLOB in;
    in.cbData = static_cast<DWORD>(utf8Plain.size());
    in.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(utf8Plain.data()));
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"AppProxySwitch proxy password", nullptr, nullptr,
                          nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    std::string b64 = base64Encode(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return b64;
}

std::string unprotectFromBase64(std::string_view base64, bool* ok) {
    if (ok) *ok = false;
    if (base64.empty()) {
        if (ok) *ok = true;
        return {};
    }
    std::vector<uint8_t> blob;
    if (!base64Decode(base64, blob) || blob.empty()) return {};
    DATA_BLOB in;
    in.cbData = static_cast<DWORD>(blob.size());
    in.pbData = blob.data();
    DATA_BLOB out{};
    LPWSTR desc = nullptr;
    if (!CryptUnprotectData(&in, &desc, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    if (desc) LocalFree(desc);
    std::string plain(reinterpret_cast<char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    if (ok) *ok = true;
    return plain;
}

bool isProcessElevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION te{};
    DWORD len = 0;
    if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &len)) {
        elevated = te.TokenIsElevated;
    }
    CloseHandle(token);
    return elevated != FALSE;
}

}  // namespace aps::crypto
