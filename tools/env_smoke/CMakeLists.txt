cmake_minimum_required(VERSION 3.20)
project(env_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 源码是 UTF-8（含中文注释/字符串），MSVC 必须显式指定，否则按 GBK(936) 解析会报 C4819/C2001
if(MSVC)
    add_compile_options(/utf-8)
endif()

# ---------------------------------------------------------------------------
# Npcap：抓包库验收程序
# ---------------------------------------------------------------------------
if(NOT DEFINED NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
endif()
if(NOT NPCAP_SDK_DIR)
    message(FATAL_ERROR "未找到 Npcap SDK：请设置环境变量 NPCAP_SDK_DIR 或传入 -DNPCAP_SDK_DIR=<路径>")
endif()
message(STATUS "Npcap SDK : ${NPCAP_SDK_DIR}")

add_executable(npcap_smoke npcap_smoke.cpp)
target_include_directories(npcap_smoke PRIVATE "${NPCAP_SDK_DIR}/Include")
target_link_libraries(npcap_smoke PRIVATE
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    ws2_32
    advapi32
)

# ---------------------------------------------------------------------------
# Qt 6 Widgets：GUI 框架验收程序（找不到 Qt 时自动跳过）
# ---------------------------------------------------------------------------
option(BUILD_QT_SMOKE "构建 Qt Widgets 验收程序" ON)
if(BUILD_QT_SMOKE)
    find_package(Qt6 QUIET COMPONENTS Widgets)
    if(Qt6_FOUND)
        message(STATUS "Qt version: ${Qt6_VERSION}")
        add_executable(qt_smoke qt_smoke.cpp)
        target_link_libraries(qt_smoke PRIVATE Qt6::Widgets)
    else()
        message(STATUS "未找到 Qt6：跳过 qt_smoke（如需构建请传 -DCMAKE_PREFIX_PATH=<Qt>/msvc2022_64）")
    endif()
endif()
