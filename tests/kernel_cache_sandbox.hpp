#pragma once
#include <windows.h>
#include "aps/kernel_discovery.hpp"

namespace aps::test {
struct KernelCacheSandbox {
    std::wstring directory;
    KernelCacheSandbox() {
        wchar_t temp[MAX_PATH]{};
        GetTempPathW(MAX_PATH, temp);
        directory = std::wstring(temp) + L"aps-kernel-cache-" +
                    std::to_wstring(GetCurrentProcessId()) + L"-" +
                    std::to_wstring(GetTickCount64());
        setKernelCacheDirectoryForTests(directory);
    }
    ~KernelCacheSandbox() {
        DeleteFileW((directory + L"\\kernel_cache.json").c_str());
        RemoveDirectoryW(directory.c_str());
        setKernelCacheDirectoryForTests({});
    }
};
}
