#include "aps/pipe.hpp"

#include <sddl.h>
#include <vector>

#include "aps/log.hpp"
#include "aps/protocol.hpp"
#include "aps/string_util.hpp"
#include "pipe_io.hpp"

namespace aps::ipc {

namespace {

// DACL: the launching user, SYSTEM and Administrators only.
bool buildSecurityAttributes(SECURITY_ATTRIBUTES* sa) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed);
    std::wstring userSid;
    if (needed && GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
        auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
            userSid = sidStr;
            LocalFree(sidStr);
        }
    }
    CloseHandle(token);
    if (userSid.empty()) return false;
    std::wstring sddl = L"D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;" + userSid + L")";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                              &sd, nullptr)) {
        return false;
    }
    sa->nLength = sizeof(*sa);
    sa->bInheritHandle = FALSE;
    sa->lpSecurityDescriptor = sd;
    return true;
}

}  // namespace

bool PipeServer::start(const std::wstring& name, MsgHandler onMsg, std::string* err) {
    (void)err;
    name_ = name;
    onMsg_ = std::move(onMsg);
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    stopping_.store(false);
    thread_ = std::thread([this] { acceptLoop(); });
    return true;
}

void PipeServer::stop() {
    if (stopping_.exchange(true)) return;
    if (stopEvent_) SetEvent(stopEvent_);
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        if (pipe_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(pipe_, nullptr);
            DisconnectNamedPipe(pipe_);
        }
    }
    if (thread_.joinable()) thread_.join();
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
        clientConnected_.store(false);
    }
    if (stopEvent_) CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
}

void PipeServer::acceptLoop() {
    SECURITY_ATTRIBUTES sa{};
    bool haveSa = buildSecurityAttributes(&sa);

    while (!stopping_.load()) {
        // (Re)create the pipe instance and wait for a client.
        HANDLE pipe = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lk(writeMu_);
            if (pipe_ != INVALID_HANDLE_VALUE) {
                DisconnectNamedPipe(pipe_);
                CloseHandle(pipe_);
                pipe_ = INVALID_HANDLE_VALUE;
            }
            if (stopping_.load()) break;
            SECURITY_ATTRIBUTES* psa = haveSa ? &sa : nullptr;
            pipe = CreateNamedPipeW(name_.c_str(),
                                     PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                                         PIPE_REJECT_REMOTE_CLIENTS,
                                     1, 64 * 1024, 64 * 1024, 0, psa);
            pipe_ = pipe;
        }
        if (pipe == INVALID_HANDLE_VALUE) {
            log::ef("pipe: CreateNamedPipe failed ({})", GetLastError());
            if (WaitForSingleObject(stopEvent_, 1000) == WAIT_OBJECT_0) break;
            continue;
        }
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) break;
        BOOL connected = ConnectNamedPipe(pipe, &ov);
        DWORD err = GetLastError();
        if (!connected && err == ERROR_IO_PENDING) {
            DWORD ignored = 0;
            if (!detail::awaitPending(pipe, ov, stopEvent_, INFINITE, ignored)) {
                CloseHandle(ov.hEvent);
                continue;
            }
        } else if (!connected && err != ERROR_PIPE_CONNECTED) {
            CloseHandle(ov.hEvent);
            continue;
        }
        CloseHandle(ov.hEvent);
        if (stopping_.load()) break;

        clientConnected_.store(true);
        log::d("pipe: client connected");
        readLoop(pipe);
        clientConnected_.store(false);
        log::d("pipe: client disconnected");
    }
    if (haveSa && sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
    }
}

void PipeServer::readLoop(HANDLE pipe) {
    std::string pending;
    char buf[8192];
    OVERLAPPED rov{};
    rov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    while (rov.hEvent && !stopping_.load() && clientConnected_.load()) {
        DWORD got = 0;
        ResetEvent(rov.hEvent);
        BOOL ok = ReadFile(pipe, buf, sizeof(buf), &got, &rov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            ok = detail::awaitPending(pipe, rov, stopEvent_, INFINITE, got);
        }
        if (!ok || got == 0) break;  // disconnected
        pending.append(buf, got);
        // Dispatch complete lines.
        size_t start = 0;
        while (true) {
            size_t nl = pending.find('\n', start);
            if (nl == std::string::npos) break;
            std::string line = pending.substr(start, nl - start);
            start = nl + 1;
            if (line.size() > kMaxLine) {
                log::wf("pipe: oversized line dropped ({} bytes)", line.size());
                continue;
            }
            if (line.empty()) continue;
            json::Value msg;
            std::string errType;
            if (ipc::parseMessage(line, msg, &errType)) {
                if (onMsg_) onMsg_(msg);
            } else {
                log::wf("pipe: rejected message ({})", errType);
                const json::Value* idv = msg.find("id");
                sendLine(ipc::error(idv && idv->isNumber() ? idv->asInt() : 0, errType));
            }
        }
        if (start > 0) pending.erase(0, start);
        if (pending.size() > kMaxLine) pending.clear();  // garbage guard
    }
    if (rov.hEvent) CloseHandle(rov.hEvent);
}

bool PipeServer::sendLine(const std::string& line) {
    if (stopping_.load() || !clientConnected_.load()) return false;
    std::lock_guard<std::mutex> lk(writeMu_);
    if (stopping_.load() || !clientConnected_.load() || pipe_ == INVALID_HANDLE_VALUE) return false;
    std::string data = line;
    if (data.empty() || data.back() != '\n') data.push_back('\n');
    if (data.size() > kMaxLine) return false;
    if (!detail::writeBounded(pipe_, stopEvent_, data)) {
        // Only the GUI control channel is reset. The engine and relay flows
        // remain running; partial JSON must never leak into a later command.
        clientConnected_.store(false);
        CancelIoEx(pipe_, nullptr);
        DisconnectNamedPipe(pipe_);
        return false;
    }
    return true;
}

}  // namespace aps::ipc
