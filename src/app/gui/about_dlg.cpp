#include "about_dlg.hpp"

#include <windowsx.h>

#include <string>

#include "app.hpp"
#include "gui_config.hpp"
#include "i18n.hpp"

namespace aps::gui {

namespace {

struct DlgState {
    HWND autostartCheck = nullptr;
};

constexpr int IDC_AUTOSTART = 4001;

LRESULT CALLBACK aboutProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            auto* st = new DlgState();
            SetWindowLongPtrW(wnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));

            const std::wstring versionLine =
                std::wstring(L"AppProxySwitch ") + appVersionWide() + L"（MIT 许可）";
            auto Sc = [](int v) { return Scaled(v); };
            setLayoutDpi(GetDpiForWindow(wnd));
            const wchar_t* lines[] = {
                versionLine.c_str(),
                L"免费的 Proxifier 精简替代：按完整路径把指定程序的出站 TCP/IPv4 "
                L"经本机 SOCKS5 端口转发，其他程序直连。",
                L"不修改系统代理、不依赖/不操作 TUN、不注入 DLL、不记录网络内容。",
                L"",
                txt::kMvpNotice,
                L"",
                L"第三方组件：WinDivert 2.2.2（LGPL-3.0/GPL-2.0 双许可，官方未修改"
                L"文件，许可证见发行目录 LICENSES\\）。",
                L"WinDivert: https://github.com/basil00/WinDivert",
                L"数据存储：%LOCALAPPDATA%\\AppProxySwitch\\（config.json + logs\\）",
            };
            int y = Sc(12);
            int lineH = Scaled(22);
            for (const wchar_t* line : lines) {
                DWORD style = WS_CHILD | WS_VISIBLE;
                HWND h = CreateWindowW(L"STATIC", line, style, Sc(12), y, Sc(560), Sc(20), wnd,
                                       nullptr, cs->hInstance, nullptr);
                if (line == txt::kMvpNotice) {
                    // Long notice: give it three lines.
                    MoveWindow(h, Sc(12), y, Sc(560), Sc(66), FALSE);
                    y += Sc(58);
                }
                y += lineH;
            }
            st->autostartCheck =
                CreateWindowW(L"BUTTON", txt::kAutostart, WS_CHILD | WS_VISIBLE |
                                                              BS_AUTOCHECKBOX,
                              Sc(12), y + Sc(6), Sc(420), Sc(22), wnd,
                              reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_AUTOSTART)), cs->hInstance,
                              nullptr);
            SendMessageW(st->autostartCheck, BM_SETCHECK,
                         autostartEnabled() ? BST_CHECKED : BST_UNCHECKED, 0);
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE, Sc(486), y + Sc(36), Sc(76), Sc(26),
                          wnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)), cs->hInstance, nullptr);
            EnumChildWindows(wnd, [](HWND h, LPARAM) -> BOOL {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
                return TRUE;
            }, 0);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) DestroyWindow(wnd);
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(wnd);
            return 0;
        case WM_DESTROY: {
            auto* st = reinterpret_cast<DlgState*>(GetWindowLongPtrW(wnd, GWLP_USERDATA));
            if (st) {
                BOOL checked = SendMessageW(st->autostartCheck, BM_GETCHECK, 0, 0) ==
                               BST_CHECKED;
                setAutostart(checked != FALSE);
                delete st;
            }
            PostQuitMessage(0);
            return 0;
        }
        default:
            return DefWindowProcW(wnd, msg, wp, lp);
    }
}

}  // namespace

void showAboutDialog(HWND parent) {
    static bool registered = false;
    WNDCLASSW wc{};
    wc.lpfnWndProc = aboutProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ApsAboutDlg";
    if (!registered) {
        RegisterClassW(&wc);
        registered = true;
    }
    RECT prc{};
    GetWindowRect(parent, &prc);
    int w = Scaled(600), h = Scaled(430);
    int x = prc.left + (prc.right - prc.left - w) / 2;
    int y = prc.top + (prc.bottom - prc.top - h) / 2;
    HWND wnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"关于",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, x, y, w, h,
                               nullptr, nullptr, wc.hInstance, nullptr);
    EnableWindow(parent, FALSE);
    ShowWindow(wnd, SW_SHOW);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(wnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
}

}  // namespace aps::gui
