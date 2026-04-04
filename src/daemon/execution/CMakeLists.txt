set(DAEMON_EXECUTION_SOURCES Runner.cpp GameWhitelist.cpp)

add_library(daemon_execution ${DAEMON_EXECUTION_SOURCES})

target_include_directories(daemon_execution
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(
  daemon_execution
  PRIVATE sys_core
  PUBLIC project_headers)
