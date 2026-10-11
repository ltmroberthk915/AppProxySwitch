#pragma once
#include <winsock2.h>
#include <windows.h>
#include <atomic>
#include <functional>
#include <thread>
#include "aps/net.hpp"
#include "aps/string_util.hpp"

namespace aps::test {
// Local-only pipe server. Can forward HTTP to MockClashApi, so transport
// regressions exercise the same version/groups/delay/switch/DNS scenarios.
class MockClashPipe {
public:
    std::string name;
    std::function<std::string(const std::string&)> respond;
    ~MockClashPipe() { stop(); }
    bool start(uint16_t backend = 0, std::string fixedName = {}) {
        static std::atomic<unsigned> sequence{0};
        name = fixedName.empty() ? "\\\\.\\pipe\\aps-test-" +
            std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++sequence) : fixedName;
        pipe_ = CreateNamedPipeW(utf8ToWide(name).c_str(), PIPE_ACCESS_DUPLEX |
                    FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                    PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, nullptr);
        if (pipe_ == INVALID_HANDLE_VALUE) return false;
        stopping_ = false;
        worker_ = std::thread([this, backend] { loop(backend); });
        return true;
    }
    void stop() {
        stopping_ = true;
        if (worker_.joinable()) worker_.join();
        if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
private:
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
    bool complete(OVERLAPPED& ov, DWORD& n) {
        auto deadline = GetTickCount64() + 4000;
        while (!stopping_ && GetTickCount64() < deadline) {
            if (WaitForSingleObject(ov.hEvent, 20) == WAIT_OBJECT_0)
                return GetOverlappedResult(pipe_, &ov, &n, FALSE) != FALSE;
        }
        CancelIoEx(pipe_, &ov);
        GetOverlappedResult(pipe_, &ov, &n, TRUE);
        return false;
    }
    void loop(uint16_t backend) {
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        while (!stopping_) {
            OVERLAPPED ov{};
            ov.hEvent = event;
            ResetEvent(event);
            DWORD n = 0;
            BOOL connected = ConnectNamedPipe(pipe_, &ov);
            DWORD error = GetLastError();
            if (!connected && error != ERROR_PIPE_CONNECTED &&
                (error != ERROR_IO_PENDING || !complete(ov, n))) {
                DisconnectNamedPipe(pipe_);
                continue;
            }
            std::string req;
            while (!stopping_) {
                char buf[4096];
                ResetEvent(event);
                ov = {}; ov.hEvent = event;
                n = 0;
                if (!ReadFile(pipe_, buf, sizeof(buf), &n, &ov) &&
                    (GetLastError() != ERROR_IO_PENDING || !complete(ov, n))) break;
                if (!n) break;
                req.append(buf, n);
                auto end = req.find("\r\n\r\n");
                auto len = req.find("Content-Length: ");
                size_t bytes = len == std::string::npos ? 0 : std::stoul(req.substr(len + 16));
                if (end != std::string::npos && req.size() >= end + 4 + bytes) break;
            }
            std::string response;
            if (!req.empty()) {
                if (respond) response = respond(req);
                else if (backend) {
                    SOCKET s = net::makeTcpSocket();
                    if (net::connectWithTimeout(s, {0x7F000001, backend}, 1000, nullptr) == 0 &&
                        net::sendAll(s, req.data(), req.size(), 1000) == 0) {
                        char buf[4096];
                        int got;
                        while ((got = net::recvSome(s, buf, sizeof(buf), 1000)) > 0)
                            response.append(buf, static_cast<size_t>(got));
                    }
                    net::closeSocket(s);
                } else response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 20\r\n\r\n{\"version\":\"mock-1\"}";
            }
            if (!response.empty() && !stopping_) {
                ResetEvent(event);
                ov = {}; ov.hEvent = event;
                if (WriteFile(pipe_, response.data(), static_cast<DWORD>(response.size()), &n, &ov) ||
                    (GetLastError() == ERROR_IO_PENDING && complete(ov, n))) FlushFileBuffers(pipe_);
            }
            DisconnectNamedPipe(pipe_);
        }
        CloseHandle(event);
    }
};
}
