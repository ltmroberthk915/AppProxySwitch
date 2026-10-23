#include "aps/log.hpp"
#include "aps/pipe.hpp"
#include "aps/protocol.hpp"
#include "pipe_io.hpp"

namespace aps::ipc {

void PipeClient::start(const std::wstring& name, MsgHandler onMsg, StateHandler onState) {
    name_ = name;
    onMsg_ = std::move(onMsg);
    onState_ = std::move(onState);
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    resetEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    stopping_.store(false);
    thread_ = std::thread([this] { run(); });
}

void PipeClient::stop() {
    if (stopping_.exchange(true)) return;
    if (stopEvent_) SetEvent(stopEvent_);
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        if (pipe_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(pipe_, nullptr);
        }
    }
    if (thread_.joinable()) thread_.join();
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
        connected_.store(false);
    }
    if (stopEvent_) CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
    if (resetEvent_) CloseHandle(resetEvent_);
    resetEvent_ = nullptr;
}

void PipeClient::run() {
    std::string pending;
    while (!stopping_.load()) {
        // (Re)connect with a 1s backoff.
        HANDLE pipe = CreateFileW(name_.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                  nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            if (WaitForSingleObject(stopEvent_, 1000) == WAIT_OBJECT_0) break;
            continue;
        }
        DWORD mode = PIPE_READMODE_BYTE;
        SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
        {
            std::lock_guard<std::mutex> lk(writeMu_);
            if (stopping_.load()) {
                CloseHandle(pipe);
                break;
            }
            ResetEvent(resetEvent_);
            pipe_ = pipe;
            connected_.store(true);
        }
        if (onState_) onState_(true);

        char buf[8192];
        OVERLAPPED rov{};
        rov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        pending.clear();
        while (rov.hEvent && !stopping_.load() && connected_.load()) {
            DWORD got = 0;
            ResetEvent(rov.hEvent);
            BOOL ok = ReadFile(pipe, buf, sizeof(buf), &got, &rov);
            if (!ok && GetLastError() == ERROR_IO_PENDING) {
                ok = detail::awaitPending(pipe, rov, stopEvent_, INFINITE, got, resetEvent_);
            }
            if (!ok || got == 0) break;  // server gone
            pending.append(buf, got);
            size_t start = 0;
            while (true) {
                size_t nl = pending.find('\n', start);
                if (nl == std::string::npos) break;
                std::string line = pending.substr(start, nl - start);
                start = nl + 1;
                if (line.empty() || line.size() > kMaxLine) continue;
                json::Value msg;
                std::string errType;
                if (ipc::parseMessage(line, msg, &errType)) {
                    if (onMsg_) onMsg_(msg);
                }
            }
            if (start > 0) pending.erase(0, start);
            if (pending.size() > kMaxLine) pending.clear();
        }
        if (rov.hEvent) CloseHandle(rov.hEvent);
        connected_.store(false);
        {
            std::lock_guard<std::mutex> lk(writeMu_);
            if (pipe_ != INVALID_HANDLE_VALUE) {
                CloseHandle(pipe_);
                pipe_ = INVALID_HANDLE_VALUE;
            }
        }
        if (onState_) onState_(false);
        if (WaitForSingleObject(stopEvent_, 500) == WAIT_OBJECT_0) break;
    }
}

bool PipeClient::sendLine(const std::string& line) {
    if (stopping_.load() || !connected_.load()) return false;
    std::lock_guard<std::mutex> lk(writeMu_);
    if (stopping_.load() || !connected_.load() || pipe_ == INVALID_HANDLE_VALUE) return false;
    std::string data = line;
    if (data.empty() || data.back() != '\n') data.push_back('\n');
    if (data.size() > kMaxLine) return false;
    if (!detail::writeBounded(pipe_, stopEvent_, data)) {
        // A cancelled byte-mode write may have delivered a prefix. Reconnect
        // before another line so a later command cannot complete that prefix.
        connected_.store(false);
        // Keep the reset observable if the reader has not issued ReadFile yet.
        SetEvent(resetEvent_);
        CancelIoEx(pipe_, nullptr);
        return false;
    }
    return true;
}

}  // namespace aps::ipc
