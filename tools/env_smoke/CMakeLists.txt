cmake_minimum_required(VERSION 3.20)
project(env_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# All sources are ASCII; /utf-8 is only a safety net for MSVC.
if(MSVC)
    add_compile_options(/utf-8)
endif()

# ---------------------------------------------------------------------------
# Npcap: capture library probe
# ---------------------------------------------------------------------------
if(NOT DEFINED NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
endif()
if(NOT NPCAP_SDK_DIR)
    message(FATAL_ERROR "NPCAP_SDK_DIR is not set; pass -DNPCAP_SDK_DIR=<path>")
endif()
message(STATUS "Npcap SDK: ${NPCAP_SDK_DIR}")

add_executable(npcap_smoke npcap_smoke.cpp)
target_include_directories(npcap_smoke PRIVATE "${NPCAP_SDK_DIR}/Include")
target_link_libraries(npcap_smoke PRIVATE
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    ws2_32
    advapi32
)

# ---------------------------------------------------------------------------
# Qt 6 Widgets: GUI framework probe (skipped when Qt is not found)
# ---------------------------------------------------------------------------
option(BUILD_QT_SMOKE "Build the Qt Widgets probe" ON)
if(BUILD_QT_SMOKE)
    find_package(Qt6 QUIET COMPONENTS Widgets)
    if(Qt6_FOUND)
        message(STATUS "Qt version: ${Qt6_VERSION}")
        add_executable(qt_smoke qt_smoke.cpp)
        target_link_libraries(qt_smoke PRIVATE Qt6::Widgets)
    else()
        message(STATUS "Qt6 not found: qt_smoke will be skipped")
    endif()
endif()
