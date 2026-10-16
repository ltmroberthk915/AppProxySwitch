#pragma once

#include <windows.h>

#include <string_view>

namespace aps::ipc::detail {

constexpr DWORD kWriteTimeoutMs = 500;

// CancelIoEx requests cancellation; the OVERLAPPED and its buffer must stay
// alive until completion, including when cancellation races a normal result.
// https://learn.microsoft.com/windows/win32/api/ioapiset/nf-ioapiset-cancelioex
inline bool awaitPending(HANDLE pipe, OVERLAPPED& operation, HANDLE stopEvent,
                         DWORD timeoutMs, DWORD& transferred,
                         HANDLE resetEvent = nullptr) {
    HANDLE waits[] = {operation.hEvent, stopEvent, resetEvent};
    const DWORD waited = WaitForMultipleObjects(resetEvent ? 3 : 2, waits, FALSE, timeoutMs);
    if (waited == WAIT_OBJECT_0) {
        return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
    }
    const DWORD error = waited == WAIT_TIMEOUT ? ERROR_SEM_TIMEOUT
                                               : ERROR_OPERATION_ABORTED;
    CancelIoEx(pipe, &operation);
    DWORD ignored = 0;
    GetOverlappedResult(pipe, &operation, &ignored, TRUE);
    SetLastError(error);
    return false;
}

inline bool writeBounded(HANDLE pipe, HANDLE stopEvent, std::string_view data) {
    OVERLAPPED operation{};
    operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!operation.hEvent) return false;
    DWORD written = 0;
    bool ok = WriteFile(pipe, data.data(), static_cast<DWORD>(data.size()),
                        &written, &operation) != FALSE;
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = awaitPending(pipe, operation, stopEvent, kWriteTimeoutMs, written);
    }
    CloseHandle(operation.hEvent);
    return ok && written == data.size();
}

}  // namespace aps::ipc::detail
