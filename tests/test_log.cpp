#include <windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

#include "aps/log.hpp"
#include "testlib/appsw_test.h"

APS_TEST(log, concurrent_reload_preserves_complete_warning_records) {
    wchar_t temp[MAX_PATH]{};
    EXPECT_TRUE(GetTempPathW(MAX_PATH, temp) != 0);
    const auto dir = std::filesystem::path(temp) /
        (L"aps-log-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
         std::to_wstring(GetTickCount64()));
    EXPECT_TRUE(aps::log::init(dir.wstring(), aps::log::Level::Debug, 2, 1));
    std::atomic<bool> finished{false};
    std::thread reloader([&] {
        while (!finished.load()) {
            aps::log::setLevel(aps::log::Level::Debug);
            aps::log::setLevel(aps::log::Level::Warn);
        }
    });
    std::vector<std::thread> writers;
    for (int worker = 0; worker < 4; ++worker) {
        writers.emplace_back([worker] {
            for (int record = 0; record < 500; ++record) {
                aps::log::wf("marker worker={} record={}", worker, record);
                aps::log::df("optional-debug worker={} record={}", worker, record);
            }
        });
    }
    for (auto& writer : writers) writer.join();
    finished.store(true);
    reloader.join();
    aps::log::shutdown();
    std::ifstream input(dir / L"aps.log", std::ios::binary);
    std::string line;
    int warnings = 0;
    bool valid = true;
    while (std::getline(input, line)) {
        if (line.find("[WARN ] marker worker=") != std::string::npos) ++warnings;
        valid = valid && line.size() > 30 && line.back() == '\r' &&
            (line.find("[WARN ] marker worker=") != std::string::npos ||
             line.find("[DEBUG] optional-debug worker=") != std::string::npos);
    }
    EXPECT_EQ(warnings, 2000);
    EXPECT_TRUE(valid);
    input.close();
    std::filesystem::remove(dir / L"aps.log");
    std::filesystem::remove(dir);
}

APS_TEST_MAIN();
