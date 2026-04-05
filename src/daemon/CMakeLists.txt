add_subdirectory(execution)
add_subdirectory(gateway)
add_subdirectory(monitor)

add_library(odin_engine STATIC OdinEngine.cpp events/LaunchEvent.cpp
                               events/ExitEvent.cpp)

target_link_libraries(
  odin_engine
  # These MUST be PUBLIC so main.cpp can see their headers
  PUBLIC daemon_gateway sys_core ebpf_manager daemon_execution project_headers
  PRIVATE ebpf_modules)

target_include_directories(
  odin_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                     ${CMAKE_CURRENT_SOURCE_DIR}/events/include)
