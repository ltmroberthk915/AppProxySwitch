// Tray icon + context menu (打开主界面 / 开启全部规则 / 停止截流 / 退出).
#pragma once

#include <windows.h>
#include <shellapi.h>

#include <string>

namespace aps::gui {

class TrayIcon {
public:
    using NotifyIconFn = BOOL(WINAPI*)(DWORD, PNOTIFYICONDATAW);

    TrayIcon() = default;
    // Injectable only so the notification-area lifecycle can be tested
    // without touching the real desktop shell.
    explicit TrayIcon(NotifyIconFn notifyIcon) : notifyIcon_(notifyIcon) {}
    ~TrayIcon();

    bool create(HWND owner);
    // Explorer owns the notification area and discards every icon when it
    // restarts.  The local added_ flag is then stale, so this must force a
    // fresh NIM_ADD rather than going through create()'s idempotent fast path.
    bool restoreAfterTaskbarRestart();
    void remove();
    void setTooltip(const wchar_t* text);
    // Balloon notification (used once when the window is hidden to tray).
    void showBalloon(const wchar_t* title, const wchar_t* msg);
    // Shows the context menu (blocks until chosen). Returns the command id.
    int showMenu();

private:
    bool add();

    HWND owner_ = nullptr;
    bool added_ = false;
    std::wstring tooltip_;
    NotifyIconFn notifyIcon_ = Shell_NotifyIconW;
};

}  // namespace aps::gui
