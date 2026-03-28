add_executable(${PROJECT_NAME}_socket main.cpp)

target_link_libraries(${PROJECT_NAME}_socket PRIVATE daemon_control daemon_launcher sys_core)
