set(DAEMON_CONTROL_SOURCES CommandListener.cpp)

add_library(daemon_gateway ${DAEMON_CONTROL_SOURCES})

target_include_directories(daemon_gateway
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(
  daemon_gateway
  PRIVATE sys_core
  PUBLIC project_headers)
