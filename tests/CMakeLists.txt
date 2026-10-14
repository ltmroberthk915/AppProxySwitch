# Test targets. Labels:
#   unit         - pure logic, no network, no admin
#   integration  - loopback sockets (mock SOCKS5 / HTTP), no admin
#   windivert    - real driver, requires admin (SKIP when not elevated)
set(APS_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Manually invoked diagnostic, excluded from normal builds and test runs.
# Uses the production RelaySession without opening a WinDivert handle.
add_executable(aps_relay_probe EXCLUDE_FROM_ALL aps_relay_probe.cpp)
target_link_libraries(aps_relay_probe PRIVATE appsw_core)
aps_set_warnings(aps_relay_probe)
add_custom_command(TARGET aps_relay_probe POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert.dll" "$<TARGET_FILE_DIR:aps_relay_probe>")

function(aps_add_test name labels)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE appsw_core)
  target_include_directories(${name} PRIVATE ${APS_TESTS_DIR})
  target_compile_definitions(${name} PRIVATE APS_BUILD_TESTS=1)
  aps_set_warnings(${name})
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES LABELS "${labels}")
  add_custom_command(TARGET ${name} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert.dll" "$<TARGET_FILE_DIR:${name}>")
endfunction()

aps_add_test(test_json unit)
aps_add_test(test_log unit)
aps_add_test(test_config unit)
aps_add_test(test_crypt unit)
aps_add_test(test_socket_map unit)
aps_add_test(test_nat_table unit)
aps_add_test(test_packet_rewrite unit)
aps_add_test(test_path_util unit)
aps_add_test(test_rule_matcher unit)
aps_add_test(test_profile_io unit)
aps_add_test(test_region_detect unit)
aps_add_test(test_nodeclass_detect unit)
aps_add_test(test_subscription unit)
add_test(NAME test_business_diagnostic
    COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/test_business_diagnostic.ps1")
set_tests_properties(test_business_diagnostic PROPERTIES LABELS "unit")
add_test(NAME test_tls_policy_cli
    COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/test_tls_policy_cli.ps1"
    -Executable "$<TARGET_FILE:AppProxySwitch>")
set_tests_properties(test_tls_policy_cli PROPERTIES LABELS "integration")

aps_add_test(test_socks5 integration)
aps_add_test(test_relay_integration integration)
aps_add_test(test_engine_harness integration)
aps_add_test(test_ipc integration)
aps_add_test(test_rules_view integration)
target_link_libraries(test_rules_view PRIVATE appsw_gui)
aps_add_test(test_connections_view integration)
target_link_libraries(test_connections_view PRIVATE appsw_gui)
aps_add_test(test_tray unit)
target_link_libraries(test_tray PRIVATE appsw_gui)
aps_add_test(test_main_window integration)
target_link_libraries(test_main_window PRIVATE appsw_gui)

aps_add_test(test_clash_api integration)
aps_add_test(test_verge_subscription integration)
aps_add_test(test_dns_rewrite unit)
aps_add_test(test_tls_client_hello unit)
aps_add_test(test_doh_resolver integration)
aps_add_test(test_kernel_discovery integration)

# --- e2e (real WinDivert driver; needs admin) ---------------------------------
add_executable(aps_test_client e2e/test_client.cpp)
target_compile_definitions(aps_test_client PRIVATE APS_BUILD_TESTS=1)
target_link_libraries(aps_test_client PRIVATE ws2_32)
aps_set_warnings(aps_test_client)

add_executable(e2e_windivert e2e/e2e_windivert.cpp)
target_link_libraries(e2e_windivert PRIVATE appsw_core)
target_include_directories(e2e_windivert PRIVATE ${APS_TESTS_DIR})
target_compile_definitions(e2e_windivert PRIVATE APS_BUILD_TESTS=1)
aps_set_warnings(e2e_windivert)
add_test(NAME e2e_windivert COMMAND e2e_windivert)
set_tests_properties(e2e_windivert PROPERTIES
  LABELS "windivert"
  SKIP_RETURN_CODE 77)
add_custom_command(TARGET e2e_windivert POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert.dll"
    "${APS_WINDIVERT_ROOT}/bin/x64/WinDivert64.sys"
    "$<TARGET_FILE_DIR:e2e_windivert>")
# The e2e test spawns copies of the client exe as (non-)rule processes.
add_custom_command(TARGET e2e_windivert POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$<TARGET_FILE:aps_test_client>" "$<TARGET_FILE_DIR:e2e_windivert>/aps_test_client.exe")
