cmake_minimum_required(VERSION 3.14)
project(p101_tool_event_tests C CXX)
enable_testing()
find_package(Threads REQUIRED)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(p101_tool_event_under_test STATIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/event.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/lifecycle.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/ownership.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/receipt.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/summary.c"
)
target_include_directories(p101_tool_event_under_test PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../lib_error/include"
)

add_library(p101_error_under_test STATIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../../lib_error/src/error.c"
)
target_include_directories(p101_error_under_test PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../../lib_error/include"
)

add_executable(test_p101_tool_event test_event.c)
target_link_libraries(test_p101_tool_event PRIVATE p101_tool_event_under_test p101_error_under_test Threads::Threads)
target_compile_definitions(test_p101_tool_event PRIVATE
        P101_TOOL_EVENT_FINGERPRINT_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/fingerprint.txt")
add_test(NAME test_p101_tool_event COMMAND test_p101_tool_event)

add_executable(test_p101_tool_event_headers_cxx test_headers.cpp)
target_link_libraries(test_p101_tool_event_headers_cxx PRIVATE p101_tool_event_under_test p101_error_under_test)
add_test(NAME test_p101_tool_event_headers_cxx COMMAND test_p101_tool_event_headers_cxx)
