#include "rule_edit_dlg.hpp"

#include <commdlg.h>

#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "app.hpp"
#include "i18n.hpp"

namespace aps::gui {

namespace {

struct DlgState {
    HWND wnd = nullptr;
    HWND nameEdit = nullptr;
    HWND pathEdit = nullptr;
    HWND childrenCheck = nullptr;
    HWND outletCombo = nullptr;
    HWND actionCombo = nullptr;
    Rule rule;
    const std::vector<Outlet>* outlets = nullptr;
    bool ok = false;
};

constexpr int IDC_NAME = 2001;
constexpr int IDC_PATH = 2002;
constexpr int IDC_BROWSE = 2003;
constexpr int IDC_CHILDREN = 2004;
constexpr int IDC_OUTLET = 2005;
constexpr int IDC_ACTION = 2006;
constexpr int IDC_OK = IDOK;
constexpr int IDC_CANCEL = IDCANCEL;

void onBrowse(HWND wnd, DlgState* st) {
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = wnd;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"可执行文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn)) {
        // Version-robust form: version-bearing directory segments become '*'
        // so the rule survives app auto-updates (e.g. Store apps whose
        // install dir embeds the version).
        SetWindowTextW(st->pathEdit, versionRobustPath(file).c_str());
        if (GetWindowTextLengthW(st->nameEdit) == 0) {
            SetWindowTextW(st->nameEdit, baseName(file).c_str());
        }
    }
}

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
            CreateWindowW(L"STATIC", L"名称：", WS_CHILD | WS_VISIBLE, Sc(12), Sc(14),
                          Sc(60), Sc(20), wnd, nullptr, cs->hInstance, nullptr);
            st->nameEdit = CreateWindowW(L"EDIT", L"",
                                         WS_CHILD | WS_VISIBLE | WS_BORDER |
                                             ES_AUTOHSCROLL,
                                         Sc(76), Sc(12), Sc(380), Sc(22), wnd,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_NAME)),
                                         cs->hInstance, nullptr);
            CreateWindowW(L"STATIC", L"路径：", WS_CHILD | WS_VISIBLE, Sc(12), Sc(44),
                          Sc(60), Sc(20), wnd, nullptr, cs->hInstance, nullptr);
            st->pathEdit = CreateWindowW(L"EDIT", L"",
                                         WS_CHILD | WS_VISIBLE | WS_BORDER |
                                             ES_AUTOHSCROLL,
                                         Sc(76), Sc(42), Sc(380), Sc(22), wnd,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PATH)),
                                         cs->hInstance, nullptr);
            CreateWindowW(L"BUTTON", L"浏览...", WS_CHILD | WS_VISIBLE, Sc(466),
                          Sc(41), Sc(70), Sc(24), wnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BROWSE)),
                          cs->hInstance, nullptr);
            st->childrenCheck = CreateWindowW(
                L"BUTTON", L"覆盖整个应用程序目录（推荐：主程序更新/子进程也不漏）",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, Sc(12), Sc(76), Sc(430),
                Sc(22), wnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CHILDREN)),
                cs->hInstance, nullptr);
            CreateWindowW(L"STATIC", L"出口", WS_CHILD | WS_VISIBLE, Sc(12), Sc(106),
                          Sc(50), Sc(20), wnd, nullptr, cs->hInstance, nullptr);
            st->outletCombo = CreateWindowW(
                L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
                Sc(66), Sc(104), Sc(240), Sc(300), wnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_OUTLET)),
                cs->hInstance, nullptr);
            {
                int selIdx = 0;
                int idx = 0;
                SendMessageW(st->outletCombo, CB_ADDSTRING, 0,
                             reinterpret_cast<LPARAM>(L"默认出口"));
                SendMessageW(st->outletCombo, CB_SETITEMDATA, idx, 0);
                ++idx;
                if (st->outlets) {
                    for (const auto& o : *st->outlets) {
                        SendMessageW(st->outletCombo, CB_ADDSTRING, 0,
                                     reinterpret_cast<LPARAM>(utf8ToWide(o.name).c_str()));
                        SendMessageW(st->outletCombo, CB_SETITEMDATA, idx,
                                     reinterpret_cast<LPARAM>(&o));
                        if (o.id == st->rule.outlet) selIdx = idx;
                        ++idx;
                    }
                }
                SendMessageW(st->outletCombo, CB_SETCURSEL, selIdx, 0);
            }
            CreateWindowW(L"STATIC", txt::kRuleActionLabel, WS_CHILD | WS_VISIBLE,
                          Sc(12), Sc(140), Sc(50), Sc(20), wnd, nullptr,
                          cs->hInstance, nullptr);
            st->actionCombo = CreateWindowW(
                L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
                Sc(66), Sc(138), Sc(240), Sc(300), wnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_ACTION)),
                cs->hInstance, nullptr);
            {
                // itemdata = 0/1/2 (integers, not pointers — invariant across
                // config versions): proxy / direct / block.
                static const wchar_t* actions[] = {
                    txt::kActionProxy, txt::kActionDirect, txt::kActionBlock};
                int sel = 0;
                for (int i = 0; i < 3; ++i) {
                    SendMessageW(st->actionCombo, CB_ADDSTRING, 0,
                                 reinterpret_cast<LPARAM>(actions[i]));
                    SendMessageW(st->actionCombo, CB_SETITEMDATA, i, i);
                    if ((st->rule.action == "direct" && i == 1) ||
                        (st->rule.action == "block" && i == 2)) {
                        sel = i;
                    }
                }
                SendMessageW(st->actionCombo, CB_SETCURSEL, sel, 0);
            }
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE, Sc(380), Sc(174),
                          Sc(70), Sc(26), wnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_OK)),
                          cs->hInstance, nullptr);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE, Sc(460), Sc(174),
                          Sc(70), Sc(26), wnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CANCEL)),
                          cs->hInstance, nullptr);
            for (HWND h : {st->nameEdit, st->pathEdit, st->childrenCheck}) {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
            }
            EnumChildWindows(wnd, [](HWND h, LPARAM) -> BOOL {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
                return TRUE;
            }, 0);
            SetWindowTextW(st->nameEdit, utf8ToWide(st->rule.name).c_str());
            SetWindowTextW(st->pathEdit, utf8ToWide(st->rule.path).c_str());
            SendMessageW(st->childrenCheck, BM_SETCHECK,
                         st->rule.includeChildren ? BST_CHECKED : BST_UNCHECKED, 0);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (id == IDC_BROWSE) onBrowse(wnd, st);
            else if (id == IDC_OK) {
                wchar_t name[512] = L"", path[MAX_PATH * 2] = L"";
                GetWindowTextW(st->nameEdit, name, 512);
                GetWindowTextW(st->pathEdit, path, sizeof(path) / sizeof(wchar_t));
                std::wstring wpath(path);
                if (wpath.size() < 3 || wpath[1] != L':') {
                    MessageBoxW(wnd, L"请输入完整的 EXE 绝对路径（例如 C:\\Apps\\App.exe）",
                                txt::kAppTitle, MB_ICONWARNING);
                    return 0;
                }
                st->rule.name = wideToUtf8(name);
                st->rule.path = wideToUtf8(path);
                st->rule.includeChildren =
                    SendMessageW(st->childrenCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
                // Store apps are the canonical "must cover children" case:
                // their agent modes run on sub-processes (measured: ChatGPT
                // desktop's work mode = app\resources\codex.exe; with
                // children off that process goes direct and the app loops on
                // "Reconnecting waiting for network" forever).
                if (!st->rule.includeChildren) {
                    std::wstring lower;
                    for (wchar_t c : wpath) {
                        lower.push_back(c >= L'A' && c <= L'Z' ? c - L'A' + L'a'
                                                              : c);
                    }
                    if (lower.find(L"windowsapps") != std::wstring::npos) {
                        MessageBoxW(
                            wnd,
                            L"提示：该路径位于商店应用目录。商店应用会随更新改变目录，"
                            L"且部分功能运行在子进程上（如 ChatGPT 的工作模式）。\n\n"
                            L"建议保持勾选「覆盖整个应用程序目录」，否则更新或子进程"
                            L"会导致规则失效、程序无法联网。",
                            txt::kAppTitle, MB_ICONINFORMATION);
                    }
                }
                {
                    LRESULT sel = SendMessageW(st->outletCombo, CB_GETCURSEL, 0, 0);
                    if (sel >= 0) {
                        LPARAM data = SendMessageW(st->outletCombo, CB_GETITEMDATA, sel, 0);
                        if (data != 0) {
                            st->rule.outlet =
                                reinterpret_cast<const Outlet*>(data)->id;
                        } else {
                            st->rule.outlet.clear();  // default outlet
                        }
                    }
                }
                {
                    LRESULT sel = SendMessageW(st->actionCombo, CB_GETCURSEL, 0, 0);
                    if (sel >= 0) {
                        LPARAM data = SendMessageW(st->actionCombo, CB_GETITEMDATA, sel, 0);
                        st->rule.action = data == 1 ? "direct"
                                          : data == 2 ? "block"
                                                      : "proxy";
                    }
                }
                st->ok = true;
                DestroyWindow(wnd);
            } else if (id == IDCANCEL) {
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

}  // namespace

std::optional<Rule> showRuleEditDialog(HWND parent, const Rule* edit,
                                       const std::vector<Outlet>* outlets) {
    static bool registered = false;
    WNDCLASSW wc{};
    wc.lpfnWndProc = dlgProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ApsRuleEditDlg";
    if (!registered) {
        RegisterClassW(&wc);
        registered = true;
    }

    DlgState st;
    st.rule = edit ? *edit : Rule{};
    st.outlets = outlets;
    if (st.rule.id.empty()) st.rule.id = newId();
    if (st.rule.name.empty() && !st.rule.path.empty()) {
        st.rule.name = wideToUtf8(baseName(utf8ToWide(st.rule.path)));
    }

    RECT prc{};
    GetWindowRect(parent, &prc);
    int w = Scaled(570), h = Scaled(248);
    int x = prc.left + (prc.right - prc.left - w) / 2;
    int y = prc.top + (prc.bottom - prc.top - h) / 2;
    HWND wnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName,
                               edit ? L"编辑规则" : L"添加规则",
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
    if (st.ok) return st.rule;
    return std::nullopt;
}

}  // namespace aps::gui
