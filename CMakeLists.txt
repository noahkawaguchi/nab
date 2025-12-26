cmake_minimum_required(VERSION 3.25)
project(nab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PcapPlusPlus REQUIRED)

# Core library (shared between main executable and tests)
add_library(nab_lib
    src/capture_session.cpp
    src/packet_filter.cpp
    src/packet_parser.cpp
    src/protocol_types.cpp
)

# Linking to nab_lib requires PcapPlusPlus and headers in src
target_link_libraries(nab_lib PUBLIC PcapPlusPlus::PcapPlusPlus)
target_include_directories(nab_lib PUBLIC src)

# Build the main executable
add_executable(nab src/main.cpp)
target_link_libraries(nab PRIVATE nab_lib)

# Build tests
find_package(Catch2 3 REQUIRED)
add_executable(nab_tests
    tests/test_ethernet_parsing.cpp
    tests/test_ipv4_parsing.cpp
    tests/test_packet_filter.cpp
    tests/test_protocol_utils.cpp
)
target_link_libraries(nab_tests PRIVATE nab_lib Catch2::Catch2WithMain)

# Integrate with CTest
include(CTest)
include(Catch)
catch_discover_tests(nab_tests)
