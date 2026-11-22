cmake_minimum_required(VERSION 3.20)
project(sss_sniffer VERSION 0.1.0 LANGUAGES CXX)

# Source files are UTF-8: comments are ASCII, UI strings are Chinese.
# /utf-8 keeps MSVC from interpreting the sources as GBK (code page 936).
if(MSVC)
    add_compile_options(/utf-8 /W3)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# Npcap SDK: pass -DNPCAP_SDK_DIR=<path> or export the environment variable.
# Nothing links against it yet; the capture module will use it in the next step.
if(NOT DEFINED NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
endif()

# ---------------------------------------------------------------- model layer
add_library(sss_model STATIC
    src/model/PacketRecord.h
    src/model/SamplePackets.h
    src/model/SamplePackets.cpp
)
target_include_directories(sss_model PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(sss_model PUBLIC Qt6::Core)

# ------------------------------------------------------------------- ui layer
add_library(sss_ui STATIC
    src/ui/PacketTableModel.h
    src/ui/PacketTableModel.cpp
    src/app/MainWindow.h
    src/app/MainWindow.cpp
)
target_link_libraries(sss_ui PUBLIC sss_model Qt6::Widgets)

# --------------------------------------------------------------- application
# WIN32 subsystem: no console window follows the GUI. `--selftest` re-attaches
# to the parent console when one exists, so exit codes stay scriptable.
add_executable(sss_sniffer WIN32 src/main.cpp)
target_link_libraries(sss_sniffer PRIVATE sss_ui)

# Convenience: Qt runtime DLLs are found through PATH during development.
# Run windeployqt on sss_sniffer.exe before shipping a standalone build.
