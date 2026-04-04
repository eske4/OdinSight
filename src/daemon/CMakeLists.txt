add_subdirectory(execution)
add_subdirectory(gateway)
add_subdirectory(monitor)
add_subdirectory(session)

add_library(odin_engine STATIC OdinEngine.cpp)

target_link_libraries(
  odin_engine
  # These MUST be PUBLIC so main.cpp can see their headers
  PUBLIC daemon_session daemon_gateway sys_core ebpf_manager daemon_execution
  # These can stay PRIVATE if they are only used in .cpp files
  PRIVATE ebpf_modules sys_core
  PUBLIC project_headers)

target_include_directories(odin_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
