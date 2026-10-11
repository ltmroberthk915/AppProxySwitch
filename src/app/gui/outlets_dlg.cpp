#include "outlets_dlg.hpp"

#include <windowsx.h>

#include <string>

#include "aps/dpapi.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "app.hpp"
#include "i18n.hpp"

namespace aps::gui {

namespace {

constexpr int IDC_LIST = 4101;
constexpr int IDC_ADD = 4102;
constexpr int IDC_EDIT = 4103;
constexpr int IDC_DEL = 4104;
constexpr int IDC_CLOSE = 4105;
constexpr int IDC_ACTIVATE = 4106;   // enable this outlet, disable the rest
constexpr int IDC_DISABLE = 4107;    // disable this outlet (zero cost)

struct DlgState {
    HWND wnd = nullptr;
    HWND list = nullptr;
    std::vector<Outlet>* outlets = nullptr;
    bool confirmed = false;
};

void refreshList(DlgState* st) {
    SendMessageW(st->list, LB_RESETCONTENT, 0, 0);
    for (const auto& o : *st->outlets) {
        std::wstring line = (o.enabled ? L"[启用] " : L"[停用] ") + utf8ToWide(o.name) +
                            L"  (" + utf8ToWide(o.host) + L":" +
                            std::to_wstring(o.port) + L")";
        SendMessageW(st->list, LB_ADDSTRING, 0,
                     reinterpret_cast<LPARAM>(line.c_str()));
    }
}

// ---- single-outlet field editor (reused for add & edit) ---------------------
struct FieldState {
    HWND wnd = nullptr;
    HWND name = nullptr, host = nullptr, port = nullptr, user = nullptr,
         pass = nullptr, apiHost = nullptr, apiPort = nullptr, apiSecret = nullptr;
    Outlet outlet;
    bool ok = false;
};

constexpr int IDC_F_NAME = 4201, IDC_F_HOST = 4202, IDC_F_PORT = 4203,
              IDC_F_USER = 4204, IDC_F_PASS = 4205, IDC_F_APIHOST = 4206,
              IDC_F_APIPORT = 4207, IDC_F_APISECRET = 4208;

LRESULT CALLBACK fieldProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<FieldState*>(GetWindowLongPtrW(wnd, GWLP_USERDATA));
    switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            st = reinterpret_cast<FieldState*>(cs->lpCreateParams);
            SetWindowLongPtrW(wnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
            st->wnd = wnd;
            auto Sc = [](int v) { return Scaled(v); };
            setLayoutDpi(GetDpiForWindow(wnd));
            auto mkLabel = [&](const wchar_t* t, int x, int y, int w) {
                CreateWindowW(L"STATIC", t, WS_CHILD | WS_VISIBLE, Sc(x), Sc(y), Sc(w),
                              Sc(20), wnd, nullptr, cs->hInstance, nullptr);
            };
            auto mkEdit = [&](int id, int x, int y, int w, const wchar_t* text,
                              DWORD style = 0) {
                return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", text,
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                           ES_AUTOHSCROLL | style,
                                       Sc(x), Sc(y), Sc(w), Sc(22), wnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                       cs->hInstance, nullptr);
            };
            mkLabel(L"名称", 12, 12, 60);
            st->name = mkEdit(IDC_F_NAME, 80, 10, 240, utf8ToWide(st->outlet.name).c_str());
            mkLabel(L"地址", 12, 42, 60);
            st->host = mkEdit(IDC_F_HOST, 80, 40, 120, utf8ToWide(st->outlet.host).c_str());
            mkLabel(L"端口(0=自动)", 210, 42, 110);
            st->port = mkEdit(IDC_F_PORT, 320, 40, 70,
                              std::to_wstring(st->outlet.port).c_str(), ES_NUMBER);
            mkLabel(L"用户名", 12, 72, 60);
            st->user = mkEdit(IDC_F_USER, 80, 70, 120, utf8ToWide(st->outlet.username).c_str());
            mkLabel(L"密码", 210, 72, 40);
            st->pass = mkEdit(IDC_F_PASS, 250, 70, 120, L"", ES_PASSWORD);
            mkLabel(L"API地址(可选)", 12, 102, 100);
            st->apiHost = mkEdit(IDC_F_APIHOST, 120, 100, 100,
                                 utf8ToWide(st->outlet.clashApi.host).c_str());
            mkLabel(L"API端口(0=自动)", 230, 102, 110);
            st->apiPort = mkEdit(IDC_F_APIPORT, 340, 100, 60,
                                 std::to_wstring(st->outlet.clashApi.port).c_str(),
                                 ES_NUMBER);
            mkLabel(L"API密钥(可选)", 12, 132, 100);
            st->apiSecret = mkEdit(IDC_F_APISECRET, 120, 130, 200, L"", ES_PASSWORD);
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE, Sc(340), Sc(168),
                          Sc(70), Sc(26), wnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)),
                          cs->hInstance, nullptr);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE, Sc(420), Sc(168),
                          Sc(70), Sc(26), wnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)),
                          cs->hInstance, nullptr);
            EnumChildWindows(wnd, [](HWND h, LPARAM) -> BOOL {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
                return TRUE;
            }, 0);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wp) == IDCANCEL) {
                DestroyWindow(wnd);
            } else if (LOWORD(wp) == IDOK) {
                wchar_t name[128] = L"", host[64] = L"", port[8] = L"", user[128] = L"",
                        pass[128] = L"", ah[64] = L"", ap[8] = L"", as[256] = L"";
                GetWindowTextW(st->name, name, 128);
                GetWindowTextW(st->host, host, 64);
                GetWindowTextW(st->port, port, 8);
                GetWindowTextW(st->user, user, 128);
                GetWindowTextW(st->pass, pass, 128);
                GetWindowTextW(st->apiHost, ah, 64);
                GetWindowTextW(st->apiPort, ap, 8);
                GetWindowTextW(st->apiSecret, as, 256);
                if (wcslen(host) == 0) wcscpy_s(host, L"127.0.0.1");
                int p = _wtoi(port);
                if (p < 1 || p > 65535) p = 7890;
                st->outlet.name = wideToUtf8(name);
                st->outlet.host = wideToUtf8(host);
                st->outlet.port = p;
                st->outlet.username = wideToUtf8(user);
                if (wcslen(pass) > 0) {
                    st->outlet.passwordEnc = crypto::protectToBase64(wideToUtf8(pass));
                }
                st->outlet.clashApi.host = wideToUtf8(ah);
                st->outlet.clashApi.port = _wtoi(ap);
                if (wcslen(as) > 0) {
                    st->outlet.clashApi.secretEnc =
                        crypto::protectToBase64(wideToUtf8(as));
                }
                st->ok = true;
                DestroyWindow(wnd);
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

bool showFieldDialog(HWND parent, Outlet& outlet) {
    static bool registered = false;
    WNDCLASSW wc{};
    wc.lpfnWndProc = fieldProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ApsOutletFieldDlg";
    if (!registered) {
        RegisterClassW(&wc);
        registered = true;
    }
    FieldState st;
    st.outlet = outlet;
    RECT prc{};
    GetWindowRect(parent, &prc);
    int w = Scaled(520), h = Scaled(240);
    int x = prc.left + (prc.right - prc.left - w) / 2;
    int y = prc.top + (prc.bottom - prc.top - h) / 2;
    HWND wnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"编辑出口",
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
    if (st.ok) outlet = std::move(st.outlet);
    return st.ok;
}

// ---- main list dialog ---------------------------------------------------------
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
            CreateWindowW(L"STATIC", L"出口列表（不同端口/订阅/代理软件）",
                          WS_CHILD | WS_VISIBLE, Sc(12), Sc(10), Sc(400), Sc(20), wnd,
                          nullptr, cs->hInstance, nullptr);
            st->list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                           WS_VSCROLL | LBS_NOTIFY,
                                       Sc(12), Sc(36), Sc(540), Sc(220), wnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LIST)),
                                       cs->hInstance, nullptr);
            auto mkBtn = [&](const wchar_t* t, int id, int x) {
                CreateWindowW(L"BUTTON", t, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                              Sc(x), Sc(268), Sc(80), Sc(26), wnd,
                              reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                              cs->hInstance, nullptr);
            };
            mkBtn(L"添加", IDC_ADD, 12);
            mkBtn(L"编辑", IDC_EDIT, 100);
            mkBtn(L"删除", IDC_DEL, 188);
            mkBtn(L"设为激活", IDC_ACTIVATE, 276);
            mkBtn(L"停用", IDC_DISABLE, 374);
            mkBtn(L"关闭", IDC_CLOSE, 472);
            EnumChildWindows(wnd, [](HWND h, LPARAM) -> BOOL {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
                return TRUE;
            }, 0);
            refreshList(st);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            int sel = static_cast<int>(SendMessageW(st->list, LB_GETCURSEL, 0, 0));
            if (id == IDC_ADD) {
                Outlet o;
                o.id = newId();
                if (showFieldDialog(wnd, o)) {
                    st->outlets->push_back(std::move(o));
                    refreshList(st);
                }
            } else if (id == IDC_EDIT && sel >= 0) {
                Outlet o = (*st->outlets)[sel];
                if (showFieldDialog(wnd, o)) {
                    (*st->outlets)[sel] = std::move(o);
                    refreshList(st);
                }
            } else if (id == IDC_DEL && sel >= 0) {
                st->outlets->erase(st->outlets->begin() + sel);
                refreshList(st);
            } else if (id == IDC_ACTIVATE && sel >= 0) {
                // Activate this outlet; deactivate ALL others (single-billing).
                for (size_t i = 0; i < st->outlets->size(); ++i) {
                    (*st->outlets)[i].enabled = (i == static_cast<size_t>(sel));
                }
                refreshList(st);
            } else if (id == IDC_DISABLE && sel >= 0) {
                (*st->outlets)[sel].enabled = false;
                refreshList(st);
            } else if (id == IDC_CLOSE || id == IDCANCEL) {
                st->confirmed = true;
                DestroyWindow(wnd);
            }
            return 0;
        }
        case WM_CLOSE:
            st->confirmed = true;
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

bool showOutletsDialog(HWND parent, std::vector<Outlet>& outlets) {
    static bool registered = false;
    WNDCLASSW wc{};
    wc.lpfnWndProc = dlgProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ApsOutletsDlg";
    if (!registered) {
        RegisterClassW(&wc);
        registered = true;
    }
    DlgState st;
    st.outlets = &outlets;
    RECT prc{};
    GetWindowRect(parent, &prc);
    int w = Scaled(580), h = Scaled(330);
    int x = prc.left + (prc.right - prc.left - w) / 2;
    int y = prc.top + (prc.bottom - prc.top - h) / 2;
    HWND wnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"管理出口",
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
    return st.confirmed;
}

}  // namespace aps::gui
