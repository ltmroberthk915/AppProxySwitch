// SocketMap: concurrency, TTL sweep, CLOSE cleanup, PID-reuse freezing.
#include <atomic>
#include <thread>

#include "aps/socket_map.hpp"
#include "aps/string_util.hpp"
#include "aps/time_util.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {
// Deterministic fake resolver: distinct paths per pid, countable calls.
struct CountingResolver {
    std::atomic<int> calls{0};
    std::wstring operator()(uint32_t pid) {
        calls.fetch_add(1);
        return L"C:\\Apps\\proc" + std::to_wstring(pid) + L".exe";
    }
};
}  // namespace

APS_TEST(socket_map, connect_stores_frozen_path) {
    SocketMap m;
    CountingResolver r;
    m.setPathResolver([&](uint32_t pid) { return r(pid); });
    m.onConnect(0xC0A80105, 5000, 0x08080808, 443, 100, 6);
    auto e = m.find(0xC0A80105, 5000);
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(e->pid, 100u);
    EXPECT_STREQ(wideToUtf8(e->path), "C:\\Apps\\proc100.exe");
    EXPECT_EQ(e->remotePort, 443);
    EXPECT_EQ(e->protocol, 6);
    // Second connect from the same pid hits the path cache.
    m.onConnect(0xC0A80105, 5001, 0x08080808, 80, 100, 6);
    EXPECT_EQ(r.calls.load(), 1);
}

APS_TEST(socket_map, pid_reuse_replaces_entry) {
    SocketMap m;
    m.setPathResolver([](uint32_t) {
        return L"C:\\A\\first.exe";  // same path for any pid in this test
    });
    m.onConnect(0xC0A80105, 5000, 0x08080808, 443, 111, 6);
    // PID is gone; a new process reuses the same local port.
    m.setPathResolver([](uint32_t) { return L"C:\\B\\second.exe"; });
    m.onConnect(0xC0A80105, 5000, 0x09090909, 80, 222, 6);
    auto e = m.find(0xC0A80105, 5000);
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(e->pid, 222u);
    EXPECT_STREQ(wideToUtf8(e->path), "C:\\B\\second.exe");
}

APS_TEST(socket_map, close_removes_entry) {
    SocketMap m;
    m.setPathResolver([](uint32_t) { return L"C:\\x.exe"; });
    m.onConnect(0xC0A80105, 5000, 0x08080808, 443, 1, 6);
    EXPECT_TRUE(m.find(0xC0A80105, 5000).has_value());
    m.onClose(0xC0A80105, 5000);
    EXPECT_FALSE(m.find(0xC0A80105, 5000).has_value());
}

APS_TEST(socket_map, ttl_sweep_removes_stale) {
    SocketMap m;
    m.setPathResolver([](uint32_t) { return L"C:\\x.exe"; });
    m.onConnect(0xC0A80105, 5000, 0x08080808, 443, 1, 6);
    m.onConnect(0xC0A80105, 5001, 0x08080808, 443, 1, 6);
    // Fresh entries survive.
    EXPECT_EQ(m.sweep(nowMs(), 60000), 0u);
    EXPECT_EQ(m.size(), 2u);
    // ... but an ancient TTL removes them.
    EXPECT_EQ(m.sweep(nowMs() + 120000, 60000), 2u);
    EXPECT_EQ(m.size(), 0u);
}

APS_TEST(socket_map, concurrent_insert_find_close) {
    SocketMap m;
    m.setPathResolver([](uint32_t pid) { return L"C:\\p" + std::to_wstring(pid) + L".exe"; });
    constexpr int kThreads = 8;
    constexpr int kIters = 4000;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < kIters; ++i) {
                uint32_t ip = 0xC0A80100 + t;
                uint16_t port = static_cast<uint16_t>(1024 + (i % 1000));
                m.onConnect(ip, port, 0x08080808, 443, 1000 + t, 6);
                (void)m.find(ip, port);
                if (i % 3 == 0) m.onClose(ip, port);
            }
        });
    }
    for (auto& th : threads) th.join();
    // No crash, no exception; size is whatever remains (closed removed).
    EXPECT_TRUE(m.size() <= static_cast<size_t>(kThreads * 1000));
}

APS_TEST(socket_map, missing_path_is_reported_empty) {
    SocketMap m;
    m.setPathResolver([](uint32_t) { return L""; });  // e.g. access denied
    m.onConnect(0xC0A80105, 5000, 0x08080808, 443, 999, 6);
    auto e = m.find(0xC0A80105, 5000);
    EXPECT_TRUE(e.has_value());
    EXPECT_TRUE(e->path.empty());  // engine treats this as unresolved -> direct
}

APS_TEST_MAIN();
