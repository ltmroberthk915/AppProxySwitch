// Notification-area lifecycle tests.  Explorer discards all tray icons when
// it restarts, while the owning process keeps running and retains its local
// state.  Use a fake Shell_NotifyIcon backend so this test never modifies the
// real taskbar.
#include <windows.h>
#include <shellapi.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "app.hpp"
#include "testlib/appsw_test.h"
#include "tray.hpp"

using namespace aps::gui;

namespace {

struct NotifyCall {
    DWORD operation = 0;
    HWND owner = nullptr;
    UINT id = 0;
    UINT flags = 0;
    UINT callback = 0;
    std::wstring tooltip;
};

std::vector<NotifyCall> g_calls;
std::vector<BOOL> g_addResults;
size_t g_addIndex = 0;

BOOL WINAPI fakeNotifyIcon(DWORD operation, PNOTIFYICONDATAW nid) {
    NotifyCall call;
    call.operation = operation;
    call.owner = nid->hWnd;
    call.id = nid->uID;
    call.flags = nid->uFlags;
    call.callback = nid->uCallbackMessage;
    call.tooltip = nid->szTip;
    g_calls.push_back(std::move(call));

    if (operation == NIM_ADD && g_addIndex < g_addResults.size()) {
        return g_addResults[g_addIndex++];
    }
    return TRUE;
}

void resetFake(std::vector<BOOL> addResults = {}) {
    g_calls.clear();
    g_addResults = std::move(addResults);
    g_addIndex = 0;
}

HWND fakeOwner() {
    return reinterpret_cast<HWND>(static_cast<std::uintptr_t>(0x1234));
}

}  // namespace

APS_TEST(tray, explorer_restart_forces_readd_and_preserves_tooltip) {
    resetFake();
    {
        TrayIcon tray(fakeNotifyIcon);
        EXPECT_TRUE(tray.create(fakeOwner()));
        EXPECT_EQ(g_calls.size(), size_t{1});
        EXPECT_EQ(g_calls[0].operation, DWORD{NIM_ADD});
        EXPECT_TRUE(g_calls[0].owner == fakeOwner());
        EXPECT_EQ(g_calls[0].id, UINT{1});
        EXPECT_TRUE((g_calls[0].flags & (NIF_ICON | NIF_MESSAGE | NIF_TIP)) ==
                    (NIF_ICON | NIF_MESSAGE | NIF_TIP));
        EXPECT_EQ(g_calls[0].callback, UINT{WM_APP_TRAY});

        tray.setTooltip(L"AppProxySwitch - 运行中");
        EXPECT_EQ(g_calls.size(), size_t{2});
        EXPECT_EQ(g_calls[1].operation, DWORD{NIM_MODIFY});

        // Ordinary UI rebuilds remain idempotent.
        EXPECT_TRUE(tray.create(fakeOwner()));
        EXPECT_EQ(g_calls.size(), size_t{2});

        // TaskbarCreated bypasses the stale added_ fast path.
        EXPECT_TRUE(tray.restoreAfterTaskbarRestart());
        EXPECT_EQ(g_calls.size(), size_t{3});
        EXPECT_EQ(g_calls[2].operation, DWORD{NIM_ADD});
        EXPECT_TRUE(g_calls[2].tooltip == L"AppProxySwitch - 运行中");
    }
    EXPECT_EQ(g_calls.size(), size_t{4});
    EXPECT_EQ(g_calls[3].operation, DWORD{NIM_DELETE});
}

APS_TEST(tray, failed_initial_add_can_recover_later) {
    resetFake({FALSE, TRUE});
    {
        TrayIcon tray(fakeNotifyIcon);
        EXPECT_FALSE(tray.create(fakeOwner()));
        tray.setTooltip(L"AppProxySwitch - 引擎未连接");
        // No NIM_MODIFY is sent for an icon the Shell never accepted.
        EXPECT_EQ(g_calls.size(), size_t{1});

        EXPECT_TRUE(tray.restoreAfterTaskbarRestart());
        EXPECT_EQ(g_calls.size(), size_t{2});
        EXPECT_EQ(g_calls[1].operation, DWORD{NIM_ADD});
        EXPECT_TRUE(g_calls[1].tooltip == L"AppProxySwitch - 引擎未连接");
    }
    EXPECT_EQ(g_calls.size(), size_t{3});
    EXPECT_EQ(g_calls[2].operation, DWORD{NIM_DELETE});
}

APS_TEST_MAIN();
