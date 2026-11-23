cmake_minimum_required(VERSION 3.20)
project(sss_sniffer VERSION 0.2.0 LANGUAGES CXX)

# Every source file is pure ASCII: comments and UI strings are English only.
# /utf-8 stays as a safety net so an accidental non-ASCII literal can never be
# mis-decoded as GBK (code page 936).
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
if(NOT DEFINED NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
endif()
if(NOT NPCAP_SDK_DIR)
    message(FATAL_ERROR "NPCAP_SDK_DIR is not set; the capture module needs the Npcap SDK")
endif()
message(STATUS "Npcap SDK: ${NPCAP_SDK_DIR}")

# ---------------------------------------------------------------- model layer
add_library(sss_model STATIC
    src/model/PacketRecord.h
    src/model/SamplePackets.h
    src/model/SamplePackets.cpp
)
target_include_directories(sss_model PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(sss_model PUBLIC Qt6::Core)

# --------------------------------------------------------------- filter layer
add_library(sss_filter STATIC
    src/filter/FilterExpression.h
    src/filter/FilterExpression.cpp
)
target_link_libraries(sss_filter PUBLIC sss_model Qt6::Core)

# ------------------------------------------------------------------ flow layer
add_library(sss_flow STATIC
    src/flow/TcpFlowTracker.h
    src/flow/TcpFlowTracker.cpp
)
target_link_libraries(sss_flow PUBLIC sss_model Qt6::Core)

# ------------------------------------------------------------- protocol layer
# Pure parsing: raw bytes in, Dissection out. No sockets, no Npcap dependency,
# so the unit tests can feed it pcap samples without touching a network.
add_library(sss_protocol STATIC
    src/protocol/Dissector.h
    src/protocol/Dissector.cpp
    src/protocol/TransportDissector.h
    src/protocol/TransportDissector.cpp
    src/protocol/ApplicationDissector.h
    src/protocol/ApplicationDissector.cpp
    src/protocol/ProtocolHelpers.h
)
target_link_libraries(sss_protocol PUBLIC sss_model Qt6::Core)

# -------------------------------------------------------------- capture layer
add_library(sss_capture STATIC
    src/capture/DeviceEnumerator.h
    src/capture/DeviceEnumerator.cpp
    src/capture/CaptureThread.h
    src/capture/CaptureThread.cpp
)
target_include_directories(sss_capture PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    "${NPCAP_SDK_DIR}/Include"
)
target_link_libraries(sss_capture PUBLIC
    sss_model
    sss_protocol
    Qt6::Core
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    ws2_32
)

# ------------------------------------------------------------------- ui layer
add_library(sss_ui STATIC
    src/ui/PacketTableModel.h
    src/ui/PacketTableModel.cpp
    src/ui/PacketFilterProxyModel.h
    src/ui/PacketFilterProxyModel.cpp
    src/ui/FlowTableModel.h
    src/ui/FlowTableModel.cpp
    src/app/MainWindow.h
    src/app/MainWindow.cpp
)
target_link_libraries(sss_ui PUBLIC sss_model sss_capture sss_filter sss_flow Qt6::Widgets)

# --------------------------------------------------------------- application
# WIN32 subsystem: no console window follows the GUI. `--selftest` re-attaches
# to the parent console when one exists, so exit codes stay scriptable.
add_executable(sss_sniffer WIN32 src/main.cpp)
target_link_libraries(sss_sniffer PRIVATE sss_ui)

# Convenience: Qt runtime DLLs are found through PATH during development.
# Run windeployqt on sss_sniffer.exe before shipping a standalone build.

# ---------------------------------------------------------------------- tests
enable_testing()
add_executable(sss_tests tests/protocol_tests.cpp)
target_link_libraries(sss_tests PRIVATE sss_protocol sss_filter sss_flow)
add_test(NAME protocol_tests COMMAND sss_tests)
