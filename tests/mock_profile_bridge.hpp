#pragma once
#include <windows.h>
#include <atomic>
#include <functional>
#include <thread>
#include "aps/string_util.hpp"
#include "aps/json.hpp"

namespace aps::test {
// Hermetic same-process fixture. No real client, config, URL, or core is used.
class MockProfileBridge {
public:
    std::string controllerPipe, name;
    std::function<json::Value(const json::Value&)> respond;
    std::atomic<int> submissions{0};
    ~MockProfileBridge() { stop(); }
    bool start() {
        static std::atomic<unsigned> seq{0};
        controllerPipe = "\\\\.\\pipe\\aps-profile-test-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++seq);
        name = controllerPipe + ".aps-profile-v1";
        handle_ = CreateNamedPipeW(utf8ToWide(name).c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 8192, 8192, 0, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) return false;
        thread_ = std::thread([this] {
            while (!stop_.load()) {
                if (!ConnectNamedPipe(handle_, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) break;
                if (stop_.load()) break;
                std::string request;
                char ch = 0; DWORD n = 0;
                while (ReadFile(handle_, &ch, 1, &n, nullptr) && n && ch != '\n' && request.size() < 8192) request += ch;
                json::Value r;
                if (json::Value::parse(request, r, nullptr)) {
                    const auto* op = r.find("op");
                    if (op && op->asString() == "refresh_current") ++submissions;
                    auto response = respond ? respond(r) : json::Value::makeObject();
                    std::string bytes = response.dump() + "\n";
                    WriteFile(handle_, bytes.data(), static_cast<DWORD>(bytes.size()), &n, nullptr);
                    FlushFileBuffers(handle_);
                    ReadFile(handle_, &ch, 1, &n, nullptr); // ACK
                }
                DisconnectNamedPipe(handle_);
            }
        });
        return true;
    }
    json::Value info() const {
        auto id = json::Value::makeObject();
        id.set("core_pid", static_cast<uint32_t>(GetCurrentProcessId()));
        id.set("controller_pipe",controllerPipe);
        id.set("profile_uid","fixture");
        id.set("revision","revision-one");
        auto caps = json::Value::makeArray(); caps.append("refresh_current_no_restart");
        auto r = json::Value::makeObject();
        r.set("protocol",1);
        r.set("state","ready");
        r.set("client_pid",static_cast<uint32_t>(GetCurrentProcessId()));
        r.set("identity",id);
        r.set("capabilities",caps);
        return r;
    }
    void stop() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        stop_.store(true);
        HANDLE wake = CreateFileW(utf8ToWide(name).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (wake != INVALID_HANDLE_VALUE) CloseHandle(wake);
        CancelSynchronousIo(thread_.native_handle());
        DisconnectNamedPipe(handle_);
        if (thread_.joinable()) thread_.join();
        CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE;
    }
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::thread thread_;
    std::atomic<bool> stop_{false};
};
}
