cmake_minimum_required(VERSION 3.24)

project(AppProxySwitch
    VERSION 1.3.4
    DESCRIPTION "AppProxySwitch - per-application SOCKS5 proxy switcher"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static runtime (/MT for Release, /MTd for Debug) so the release build does
# not require the VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(APS_BUILD_TESTS "Build the test suite" ON)
option(APS_BUILD_GUI "Build the Win32 GUI (disable for headless CI smoke)" ON)
option(APS_TEST_HOOKS "Enable test-only hooks in the engine (never ship enabled)" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(WinDivert)

# ---------------------------------------------------------------------------
# appsw_common: config/json/dpapi/log/utils + IPC + SOCKS5 client
# ---------------------------------------------------------------------------
add_library(appsw_common STATIC
    src/common/json.cpp
    src/common/config.cpp
    src/common/json_config_io.cpp
    src/common/profile_io.cpp
    src/common/region_detect.cpp
    src/common/nodeclass_detect.cpp
    src/common/subscription.cpp
    src/common/dpapi.cpp
    src/common/log.cpp
    src/common/net.cpp
    src/common/path_util.cpp
    src/common/control_pipe.cpp
    src/common/string_util.cpp
    src/common/time_util.cpp
    src/ipc/protocol.cpp
    src/ipc/pipe_server.cpp
    src/ipc/pipe_client.cpp
    src/socks/socks5_client.cpp
)
target_include_directories(appsw_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(appsw_common PUBLIC
    APS_VERSION="${PROJECT_VERSION}"
    APS_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    APS_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    APS_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    $<$<CONFIG:Debug>:APS_DEBUG=1>
)
if(APS_TEST_HOOKS)
    target_compile_definitions(appsw_common PUBLIC APS_TEST_HOOKS=1)
endif()
target_link_libraries(appsw_common PUBLIC ws2_32 iphlpapi crypt32 advapi32 user32 winhttp shell32)
aps_set_warnings(appsw_common)

# ---------------------------------------------------------------------------
# appsw_core: divert abstraction, NAT, packet rewrite, relay, engine
# ---------------------------------------------------------------------------
add_library(appsw_core STATIC
    src/core/clash_api.cpp
    src/core/clash_pipe.cpp
    src/core/verge_subscription.cpp
    src/core/verge_official.cpp
    src/core/doh_resolver.cpp
    src/core/divert_windivert.cpp
    src/core/socket_map.cpp
    src/core/tcp_table.cpp
    src/core/rule_matcher.cpp
    src/core/nat_table.cpp
    src/core/dns_rewrite.cpp
    src/core/kernel_discovery.cpp
    src/core/kernel_config.cpp
    src/core/packet_rewrite.cpp
    src/core/health_monitor.cpp
    src/core/stats.cpp
    src/core/engine.cpp
    src/relay/relay_server.cpp
    src/relay/relay_session.cpp
    src/relay/tls_client_hello.cpp
)
target_link_libraries(appsw_core PUBLIC appsw_common WinDivert::WinDivert ole32 oleaut32 uiautomationcore)
aps_set_warnings(appsw_core)

# ---------------------------------------------------------------------------
# appsw_gui: Win32 UI (library so tests can drive RulesView directly)
# ---------------------------------------------------------------------------
if(APS_BUILD_GUI)
    add_library(appsw_gui STATIC
        src/app/gui/app.cpp
        src/app/gui/main_window.cpp
        src/app/gui/rules_view.cpp
        src/app/gui/connections_view.cpp
        src/app/gui/rule_edit_dlg.cpp
        src/app/gui/outlets_dlg.cpp
        src/app/gui/pick_process_dlg.cpp
        src/app/gui/tray.cpp
        src/app/gui/about_dlg.cpp
        src/app/gui/engine_client.cpp
        src/app/gui/gui_config.cpp
    )
    target_include_directories(appsw_gui PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/app/gui")
    target_compile_definitions(appsw_gui PUBLIC APS_BUILD_GUI=1)
    target_link_libraries(appsw_gui PUBLIC
        appsw_core comctl32 shell32 gdi32 ole32 rpcrt4)
    aps_set_warnings(appsw_gui)
endif()

# ---------------------------------------------------------------------------
# AppProxySwitch.exe: GUI (default mode) + engine mode (--engine)
# ---------------------------------------------------------------------------
set(APS_APP_SOURCES
    src/app/main.cpp
    src/app/engine_main.cpp
)
add_executable(AppProxySwitch
    ${APS_APP_SOURCES}
    resources/app.rc
)
if(APS_BUILD_GUI)
    set_target_properties(AppProxySwitch PROPERTIES WIN32_EXECUTABLE ON)
    target_compile_definitions(AppProxySwitch PRIVATE APS_BUILD_GUI=1)
    target_link_libraries(AppProxySwitch PRIVATE appsw_gui)
else()
    target_link_libraries(AppProxySwitch PRIVATE appsw_core)
endif()
target_include_directories(AppProxySwitch PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/resources")
# The manifest is embedded via resources/app.rc (RT_MANIFEST); disable the
# linker's auto-generated manifest to avoid CVT1100 duplicate-resource errors.
target_link_options(AppProxySwitch PRIVATE "/MANIFEST:NO")
# MAP file for crash-offset -> symbol resolution.
target_link_options(AppProxySwitch PRIVATE "/MAP:$<TARGET_FILE_DIR:AppProxySwitch>/AppProxySwitch.map")
aps_set_warnings(AppProxySwitch)

# Keep the WinDivert runtime next to every target that links it.
add_custom_command(TARGET AppProxySwitch POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert.dll"
        "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert64.sys"
        "$<TARGET_FILE_DIR:AppProxySwitch>"
    COMMENT "Copying WinDivert runtime files")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(APS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
