#include "pick_process_dlg.hpp"

#include <commctrl.h>
#include <tlhelp32.h>

#include <iterator>
#include <vector>

#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "app.hpp"
#include "i18n.hpp"

namespace aps::gui {

namespace {

struct ProcRow {
    std::wstring path;
    std::wstring name;
    DWORD pid = 0;
};

struct DlgState {
    HWND wnd = nullptr;
    HWND list = nullptr;
    std::vector<ProcRow> rows;
    std::wstring chosen;
};

LRESULT CALLBACK dlgProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<DlgState*>(GetWindowLongPtrW(wnd, GWLP_USERDATA));
    switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            st = reinterpret_cast<DlgState*>(cs->lpCreateParams);
            SetWindowLongPtrW(wnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
            st->wnd = wnd;
            auto Sc = [](int v) { return Scaled(v); };
            setLayoutDpi(GetDpiForWindow(wnd));

            CreateWindowW(L"STATIC", txt::kPickProcessTitle, WS_CHILD | WS_VISIBLE,
                          Sc(10), Sc(8), Sc(560), Sc(20), wnd, nullptr,
                          cs->hInstance, nullptr);
            st->list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                                           LVS_SINGLESEL,
                                       Sc(10), Sc(32), Sc(660), Sc(330), wnd,
                                       reinterpret_cast<HMENU>(3001), cs->hInstance,
                                       nullptr);
            ListView_SetExtendedListViewStyle(st->list, LVS_EX_FULLROWSELECT |
                                                             LVS_EX_DOUBLEBUFFER);
            LVCOLUMNW c1{}, c2{}, c3{};
            c1.mask = c2.mask = c3.mask = LVCF_TEXT | LVCF_WIDTH;
            c1.pszText = const_cast<LPWSTR>(txt::kColName);
            c1.cx = Scaled(160);
            c2.pszText = const_cast<LPWSTR>(L"PID");
            c2.cx = Scaled(70);
            c3.pszText = const_cast<LPWSTR>(txt::kColPath);
            c3.cx = Scaled(400);
            ListView_InsertColumn(st->list, 0, &c1);
            ListView_InsertColumn(st->list, 1, &c2);
            ListView_InsertColumn(st->list, 2, &c3);

            // Snapshot.
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                               pe.th32ProcessID);
                        if (!h) continue;
                        wchar_t buf[MAX_PATH * 2];
                        DWORD sz = static_cast<DWORD>(std::size(buf));
                        std::wstring path;
                        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
                            path.assign(buf, sz);
                        }
                        CloseHandle(h);
                        if (!path.empty()) {
                            st->rows.push_back(
                                ProcRow{path, baseName(path), pe.th32ProcessID});
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
            for (size_t i = 0; i < st->rows.size(); ++i) {
                LVITEMW it{};
                it.mask = LVIF_TEXT | LVIF_PARAM;
                it.iItem = static_cast<int>(i);
                std::wstring name = st->rows[i].name;
                it.pszText = name.data();
                it.lParam = static_cast<LPARAM>(i);
                ListView_InsertItem(st->list, &it);
                ListView_SetItemText(st->list, static_cast<int>(i), 1,
                    const_cast<LPWSTR>(std::to_wstring(st->rows[i].pid).c_str()));
                ListView_SetItemText(st->list, static_cast<int>(i), 2,
                    const_cast<LPWSTR>(st->rows[i].path.c_str()));
            }

            CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE, Sc(510), Sc(374), Sc(76), Sc(26),
                          wnd, reinterpret_cast<HMENU>(IDOK), cs->hInstance, nullptr);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE, Sc(594), Sc(374), Sc(76), Sc(26),
                          wnd, reinterpret_cast<HMENU>(IDCANCEL), cs->hInstance,
                          nullptr);
            EnumChildWindows(wnd, [](HWND h, LPARAM) -> BOOL {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
                return TRUE;
            }, 0);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (id == IDOK) {
                int sel = ListView_GetNextItem(st->list, -1, LVNI_SELECTED);
                if (sel >= 0 && sel < static_cast<int>(st->rows.size())) {
                    const ProcRow& r = st->rows[sel];
                    if (_wcsicmp(r.name.c_str(), L"svchost.exe") == 0 ||
                        _wcsicmp(r.name.c_str(), L"explorer.exe") == 0) {
                        MessageBoxW(wnd, txt::kWarnSystemProc, txt::kAppTitle,
                                    MB_ICONWARNING);
                    }
                    st->chosen = r.path;
                }
                DestroyWindow(wnd);
            } else if (id == IDCANCEL) {
                DestroyWindow(wnd);
            }
            return 0;
        }
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<LPNMHDR>(lp);
            if (nm->idFrom == 3001 && nm->code == NM_DBLCLK) {
                SendMessageW(wnd, WM_COMMAND, IDOK, 0);
            }
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(wnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(wnd, msg, wp, lp);
    }
}

}  // namespace

std::optional<std::wstring> showPickProcessDialog(HWND parent) {
    static bool registered = false;
    WNDCLASSW wc{};
    wc.lpfnWndProc = dlgProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ApsPickProcessDlg";
    if (!registered) {
        RegisterClassW(&wc);
        registered = true;
    }

    DlgState st;
    RECT prc{};
    GetWindowRect(parent, &prc);
    int w = Scaled(690), h = Scaled(450);
    int x = prc.left + (prc.right - prc.left - w) / 2;
    int y = prc.top + (prc.bottom - prc.top - h) / 2;
    HWND wnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName,
                               txt::kPickProcessTitle,
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, x, y, w, h,
                               nullptr, nullptr, wc.hInstance, &st);
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
    if (!st.chosen.empty()) return st.chosen;
    return std::nullopt;
}

}  // namespace aps::gui
