cmake_minimum_required(VERSION 3.16)
project(DPIEngine VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

# Protocol parsing and PCAP I/O, shared by every target.
set(CORE_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Components used only by the modular multi-threaded engine.
set(ENGINE_SOURCES
    src/dpi_engine.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
)

# --- dpi_engine: modular multi-threaded engine (rules files, wildcard domains,
#     per-thread statistics). The most complete version.
add_executable(dpi_engine src/main_dpi.cpp ${ENGINE_SOURCES} ${CORE_SOURCES})
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# --- dpi_mt: self-contained multi-threaded engine. Same LB/FP pipeline, all in
#     one translation unit. Easier to read end to end.
add_executable(dpi_mt src/dpi_mt.cpp ${CORE_SOURCES})
target_link_libraries(dpi_mt PRIVATE Threads::Threads)

# --- dpi_simple: single-threaded reference implementation. Start here.
add_executable(dpi_simple src/main_working.cpp ${CORE_SOURCES})

# --- Tests
enable_testing()
add_executable(test_sni tests/test_sni.cpp src/types.cpp)
add_test(NAME sni_classification COMMAND test_sni)
