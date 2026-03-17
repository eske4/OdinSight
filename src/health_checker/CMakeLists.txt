set(LAUNCHER_SOURCES
    HealthChecker.cpp
)

add_library(HealthChecker ${LAUNCHER_SOURCES})

target_include_directories(HealthChecker
    PUBLIC "${GLOBAL_INCLUDE_DIR}"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
