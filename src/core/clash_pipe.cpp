#include "aps/clash_pipe.hpp"

#include <windows.h>
#include <algorithm>
#include <vector>
#include "aps/string_util.hpp"

namespace aps {
bool localControllerPipe(const std::string& name) {
    return name.starts_with("\\\\.\\pipe\\") && name.size() > 9 &&
           name.find('\0') == std::string::npos &&
           name.find_first_of("\r\n/") == std::string::npos;
}

namespace {
bool sameUserProcess(uint32_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    auto sidFor = [](HANDLE proc, std::vector<BYTE>& tokenUser) {
        HANDLE token = nullptr;
        if (!OpenProcessToken(proc, TOKEN_QUERY, &token)) return false;
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        tokenUser.resize(needed);
        bool ok = needed && GetTokenInformation(token, TokenUser,
                           tokenUser.data(), needed, &needed);
        CloseHandle(token);
        return ok;
    };
    std::vector<BYTE> self, other;
    bool ok = sidFor(GetCurrentProcess(), self) && sidFor(process, other) &&
        EqualSid(reinterpret_cast<TOKEN_USER*>(self.data())->User.Sid,
                 reinterpret_cast<TOKEN_USER*>(other.data())->User.Sid);
    CloseHandle(process);
    return ok;
}

bool requestPipe(const std::string& name, uint32_t expectedPid,
                           const std::string& request, int timeoutMs,
                           std::string& response, std::string& error,
                           uint32_t* bridgeOwner) {
    response.clear();
    if (!localControllerPipe(name) || timeoutMs <= 0) {
        error = "invalid local controller pipe";
        return false;
    }
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    auto remaining = [&]() -> DWORD {
        auto now = GetTickCount64();
        return now < deadline ? static_cast<DWORD>(deadline - now) : 0;
    };
    const auto path = utf8ToWide(name);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    while (remaining()) {
        pipe = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
                               SECURITY_IDENTIFICATION, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const auto openError = GetLastError();
        const auto waitMs = remaining();
        if (openError != ERROR_PIPE_BUSY || !waitMs ||
            !WaitNamedPipeW(path.c_str(), waitMs)) break;
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        error = "controller pipe unavailable";
        return false;
    }
    ULONG owner = 0;
    if ((expectedPid || bridgeOwner) && (!GetNamedPipeServerProcessId(pipe, &owner) ||
                         (expectedPid && owner != expectedPid))) {
        CloseHandle(pipe);
        error = "controller pipe belongs to another process";
        return false;
    }
    if (bridgeOwner) {
        if (!sameUserProcess(owner)) {
            CloseHandle(pipe);
            error = "bridge account mismatch";
            return false;
        }
        *bridgeOwner = owner;
    }
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) {
        CloseHandle(pipe);
        error = "controller pipe event failed";
        return false;
    }
    auto transfer = [&](bool writing, void* data, DWORD size, DWORD& done) {
        OVERLAPPED ov{};
        ov.hEvent = event;
        ResetEvent(event);
        done = 0;
        if (!remaining()) { SetLastError(ERROR_TIMEOUT); return false; }
        BOOL ok = writing ? WriteFile(pipe, data, size, &done, &ov)
                          : ReadFile(pipe, data, size, &done, &ov);
        if (ok) return true;
        if (GetLastError() != ERROR_IO_PENDING) return false;
        if (WaitForSingleObject(event, remaining()) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            // Drain cancellation before the stack OVERLAPPED/buffer goes away.
            GetOverlappedResult(pipe, &ov, &done, TRUE);
            SetLastError(ERROR_TIMEOUT);
            return false;
        }
        return GetOverlappedResult(pipe, &ov, &done, FALSE) != FALSE;
    };
    bool success = true;
    size_t sent = 0;
    while (sent < request.size()) {
        DWORD n = 0;
        if (!transfer(true, const_cast<char*>(request.data() + sent),
                       static_cast<DWORD>(request.size() - sent), n) || !n) {
            error = "controller pipe send failed or timed out";
            success = false;
            break;
        }
        sent += n;
    }
    while (success) {
        char buf[4096];
        DWORD n = 0;
        if (!transfer(false, buf, sizeof(buf), n)) {
            const auto readError = GetLastError();
            if (readError != ERROR_BROKEN_PIPE && readError != ERROR_PIPE_NOT_CONNECTED) {
                error = "controller pipe read failed or timed out";
                success = false;
            }
            break;
        }
        if (!n) break;
        response.append(buf, n);
        if (response.size() > (bridgeOwner ? 8192u : 8u * 1024u * 1024u)) {
            error = "controller pipe reply too large";
            success = false;
        }
        if (success && bridgeOwner && response.find('\n') != std::string::npos) {
            if (response.find('\n') != response.size() - 1) {
                error = "bridge sent extra frames";
                success = false;
            } else {
                char ack = '!';
                DWORD done = 0;
                // The completed reply remains valid even if the peer closes
                // during its ACK. This is not a reason to re-submit the job.
                transfer(true, &ack, 1, done);
                response.pop_back();
                CloseHandle(event);
                CloseHandle(pipe);
                return true;
            }
        }
    }
    if (bridgeOwner && success) {
        error = "bridge reply incomplete";
        success = false;
    }
    CloseHandle(event);
    CloseHandle(pipe);
    return success;
}
} // namespace

bool requestControllerPipe(const std::string& name, uint32_t expectedPid,
                           const std::string& request, int timeoutMs,
                           std::string& response, std::string& error) {
    return requestPipe(name, expectedPid, request, timeoutMs, response, error, nullptr);
}

bool requestProfileBridgePipe(const std::string& name, uint32_t expectedPid,
                              const std::string& request, int timeoutMs,
                              uint32_t& ownerPid, std::string& response,
                              std::string& error) {
    ownerPid = 0;
    if (request.size() > 8192 || request.empty() || request.back() != '\n') {
        error = "invalid bridge frame";
        return false;
    }
    return requestPipe(name, expectedPid, request, timeoutMs, response, error, &ownerPid);
}
}
