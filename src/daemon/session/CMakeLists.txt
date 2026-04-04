set(DAEMON_SESSION_SOURCES StartupHandler.cpp)

add_library(daemon_session ${DAEMON_SESSION_SOURCES})

target_include_directories(daemon_session
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(
  daemon_session
  PRIVATE sys_core daemon_gateway daemon_execution ebpf_manager ebpf_modules
  PUBLIC project_headers)
