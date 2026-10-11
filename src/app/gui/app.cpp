#include "app.hpp"

#include <commctrl.h>

#include <atomic>
#include <cstdio>
#include <mutex>
#include <thread>

#include "aps/log.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "main_window.hpp"

namespace aps::gui {

namespace {
HFONT g_font = nullptr;
HWND g_mainHwnd = nullptr;
std::once_flag g_versionOnce;
std::wstring g_versionWide;
const wchar_t* kShowEventName = L"Local\\AppProxySwitchShowEvent";

// Boot-step tracer: append-only file so a GUI that dies before showing a
// window still leaves a trail. Removed by "清除日志" users can ignore it.
FILE* g_diag = nullptr;
// Layout DPI (window's monitor, updated at WM_CREATE / WM_DPICHANGED).
std::atomic<UINT> g_layoutDpi{[] {
    HDC dc = GetDC(nullptr);
    UINT dpi = dc ? static_cast<UINT>(GetDeviceCaps(dc, LOGPIXELSX)) : 96;
    if (dc) ReleaseDC(nullptr, dc);
    return dpi < 96 ? 96 : dpi;
}()};
void diag(const char* step) {
    if (!g_diag) return;
    std::fprintf(g_diag, "%s\n", step);
    std::fflush(g_diag);
}
LONG WINAPI crashDump(EXCEPTION_POINTERS* ep) {
    if (g_diag) {
        std::fprintf(g_diag, "CRASH code=0x%08lX addr=%p\n",
                     ep ? ep->ExceptionRecord->ExceptionCode : 0,
                     ep ? ep->ExceptionRecord->ExceptionAddress : nullptr);
        std::fflush(g_diag);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
}  // namespace

void guiDiagStep(const char* step) { diag(step); }

int Scaled(int px) {
    const double k = g_layoutDpi.load() / 96.0;
    return static_cast<int>(px * k + 0.5);
}

void setLayoutDpi(UINT dpi) {
    if (dpi >= 96) g_layoutDpi.store(dpi);
}

HFONT uiFont() {
    if (!g_font) {
        NONCLIENTMETRICSW ncm{};
        ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    }
    return g_font;
}

const wchar_t* appVersionWide() {
    std::call_once(g_versionOnce, [] {
        g_versionWide = utf8ToWide(APS_VERSION);
    });
    return g_versionWide.c_str();
}

void setMainHwnd(HWND hwnd) { g_mainHwnd = hwnd; }
HWND mainHwnd() { return g_mainHwnd; }

int runGui(HINSTANCE hInstance, int nCmdShow) {
    if (std::wstring dir = aps::appDataDir(); !dir.empty()) {
        g_diag = _wfopen((dir + L"\\gui-diag.log").c_str(), L"a");
    }
    SetUnhandledExceptionFilter(crashDump);
    diag("gui: runGui enter");

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    diag("gui: common controls ok");

    HANDLE single = CreateMutexW(nullptr, TRUE, L"Local\\AppProxySwitchGui");
    if (single != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
        // Ask the existing instance to surface itself.
        HANDLE showEvt = OpenEventW(EVENT_MODIFY_STATE, FALSE, kShowEventName);
        if (showEvt) {
            SetEvent(showEvt);
            CloseHandle(showEvt);
        }
        for (int i = 0; i < 20; ++i) {
            HWND existing = FindWindowW(L"ApsMainWindow", nullptr);
            if (existing) {
                ShowWindow(existing, SW_RESTORE);
                SetForegroundWindow(existing);
                return 0;
            }
            Sleep(50);
        }
        // No reachable window (e.g. an orphaned instance stuck in a hidden
        // window station still holding the mutex). Do not punish the user
        // with a silent no-op: fall through and create our own UI.
        log::w("another instance holds the mutex but has no reachable window; "
               "starting a new UI anyway");
    }

    // Metadata-only logs; separate file from the engine's so the two
    // processes never contend for one handle.
    std::wstring dataDir = aps::appDataDir();
    if (!dataDir.empty()) {
        log::init(dataDir + L"\\logs", log::Level::Info, 10, 5, L"aps-gui");
    }
    diag("gui: pre-create");
    MainWindow* win = MainWindow::create(hInstance);
    diag(win->hwnd() ? "gui: window created" : "gui: WINDOW CREATE FAILED");
    setMainHwnd(win->hwnd());
    (void)nCmdShow;

    // Let future instances ask us to surface (auto-reset event; a listener
    // that outlives the window simply fails harmlessly on a stale HWND).
    HANDLE showEvent = CreateEventW(nullptr, FALSE, FALSE, kShowEventName);
    if (showEvent) {
        std::thread([showEvent, hwnd = win->hwnd()]() {
            while (WaitForSingleObject(showEvent, INFINITE) == WAIT_OBJECT_0) {
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
        }).detach();
    }

    MSG msg;
    diag("gui: message loop enter");
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    diag("gui: message loop exit");
    if (single) {
        ReleaseMutex(single);
        CloseHandle(single);
    }
    delete win;
    return static_cast<int>(msg.wParam);
}

}  // namespace aps::gui
