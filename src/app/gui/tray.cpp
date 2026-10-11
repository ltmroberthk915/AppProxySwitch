#include "tray.hpp"

#include <shellapi.h>

#include "app.hpp"
#include "i18n.hpp"

namespace aps::gui {

enum {
    kTrayCmdOpen = 5001,
    kTrayCmdEnableAll = 5002,
    kTrayCmdStop = 5003,
    kTrayCmdExit = 5004,
};

TrayIcon::~TrayIcon() { remove(); }

bool TrayIcon::create(HWND owner) {
    owner_ = owner;
    if (tooltip_.empty()) tooltip_ = txt::kAppTitle;
    if (added_) return true;   // rebuild-after-DPI-change must not double-add
    return add();
}

bool TrayIcon::add() {
    if (!owner_ || !notifyIcon_) {
        added_ = false;
        return false;
    }
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = owner_;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_APP_TRAY;
    nid.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101));
    if (!nid.hIcon) nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcsncpy_s(nid.szTip, tooltip_.c_str(), _TRUNCATE);
    added_ = notifyIcon_(NIM_ADD, &nid) != FALSE;
    return added_;
}

bool TrayIcon::restoreAfterTaskbarRestart() {
    // TaskbarCreated means Explorer has lost its copy even though our local
    // flag still says the earlier NIM_ADD succeeded.
    added_ = false;
    return add();
}

void TrayIcon::remove() {
    if (!added_) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = owner_;
    nid.uID = 1;
    notifyIcon_(NIM_DELETE, &nid);
    added_ = false;
}

void TrayIcon::setTooltip(const wchar_t* text) {
    tooltip_ = text ? text : L"";
    if (!added_) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = owner_;
    nid.uID = 1;
    nid.uFlags = NIF_TIP;
    wcsncpy_s(nid.szTip, tooltip_.c_str(), _TRUNCATE);
    notifyIcon_(NIM_MODIFY, &nid);
}

void TrayIcon::showBalloon(const wchar_t* title, const wchar_t* msg) {
    if (!added_) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = owner_;
    nid.uID = 1;
    nid.uFlags = NIF_INFO;
    wcsncpy_s(nid.szInfoTitle, title, 63);
    wcsncpy_s(nid.szInfo, msg, 255);
    nid.dwInfoFlags = NIIF_INFO;
    notifyIcon_(NIM_MODIFY, &nid);
}

int TrayIcon::showMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kTrayCmdOpen, txt::kTrayOpen);
    AppendMenuW(menu, MF_STRING, kTrayCmdEnableAll, txt::kTrayEnableAll);
    AppendMenuW(menu, MF_STRING, kTrayCmdStop, txt::kTrayStop);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kTrayCmdExit, txt::kTrayExit);
    SetForegroundWindow(owner_);
    POINT pt{};
    GetCursorPos(&pt);
    int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                             pt.x, pt.y, 0, owner_, nullptr);
    DestroyMenu(menu);
    return cmd;
}

}  // namespace aps::gui
