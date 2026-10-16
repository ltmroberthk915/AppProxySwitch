// GUI process entry + shared app-wide helpers.
#pragma once

#include <windows.h>

namespace aps::gui {

int runGui(HINSTANCE hInstance, int nCmdShow);

// 12-point UI font, created once (call after init).
HFONT uiFont();

// Wide version string (built from APS_VERSION).
const wchar_t* appVersionWide();

// Boot-step diagnostics (writes to gui-diag.log when open; cheap no-op
// otherwise). Used to pinpoint "GUI never appears" issues.
void guiDiagStep(const char* step);

// DPI scaling: all layout constants are authored at 96 DPI (100%); every
// pixel value must go through Scaled() so text/buttons never overlap on
// 125%/150% display scaling. The factor is taken from the actual window's
// monitor (GetDpiForWindow), NOT from process-context APIs, which return
// misleading values depending on how/where the process was launched.
int Scaled(int px);
void setLayoutDpi(UINT dpi);   // called at WM_CREATE / WM_DPICHANGED

// Main window handle for tray/child messaging.
void setMainHwnd(HWND hwnd);
HWND mainHwnd();

// Custom message ids.
constexpr UINT WM_APP_TRAY = WM_APP + 1;      // lParam = tray event
constexpr UINT WM_APP_PIPE_MSG = WM_APP + 2;  // wParam = pointer to json::Value string (heap)
constexpr UINT WM_APP_PIPE_STATE = WM_APP + 3;  // wParam = 1 connected / 0 disconnected
constexpr UINT WM_APP_PROXY_TEST = WM_APP + 4; // lParam = pointer to result string (heap)
constexpr UINT WM_APP_SHOW = WM_APP + 5;     // request handled on the UI thread

}  // namespace aps::gui
