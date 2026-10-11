# Locate the official WinDivert 2.2.2 package under third_party/windivert.
# The package is fetched by scripts/fetch-windivert.ps1 from the official
# GitHub release with SHA-256 verification. We never vendor binaries in git.

set(APS_WINDIVERT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/windivert")

if(NOT EXISTS "${APS_WINDIVERT_ROOT}/include/windivert.h")
    message(FATAL_ERROR
        "WinDivert headers not found under ${APS_WINDIVERT_ROOT}.\n"
        "Run:  powershell -ExecutionPolicy Bypass -File scripts/fetch-windivert.ps1\n"
        "The script downloads ONLY from the official basil00/WinDivert GitHub "
        "release (v2.2.2) and verifies a pinned SHA-256.")
endif()

if(NOT EXISTS "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert.dll" OR
   NOT EXISTS "${APS_WINDIVERT_ROOT}/lib/x64/WinDivert.lib" OR
   NOT EXISTS "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert64.sys")
    message(FATAL_ERROR
        "WinDivert runtime files incomplete under ${APS_WINDIVERT_ROOT}.\n"
        "Re-run:  powershell -ExecutionPolicy Bypass -File scripts/fetch-windivert.ps1")
endif()

add_library(WinDivert SHARED IMPORTED GLOBAL)
set_target_properties(WinDivert PROPERTIES
    IMPORTED_LOCATION         "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert.dll"
    IMPORTED_IMPLIB           "${APS_WINDIVERT_ROOT}/lib/x64/WinDivert.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${APS_WINDIVERT_ROOT}/include")

add_library(WinDivert::WinDivert ALIAS WinDivert)
