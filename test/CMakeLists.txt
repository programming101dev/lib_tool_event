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

option(P101_TEST_COVERAGE "Instrument the code under test" OFF)
set(_COV "")
if(P101_TEST_COVERAGE)
    set(_COV --coverage)
endif()

add_library(p101_tool_event_under_test STATIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/event.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/lifecycle.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/model.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/model_json.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/ownership.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/receipt.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/summary.c"
)
target_include_directories(p101_tool_event_under_test PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../lib_error/include"
)
target_compile_definitions(p101_tool_event_under_test PRIVATE P101_TOOL_EVENT_TESTING=1)

add_library(p101_error_under_test STATIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../../lib_error/src/error.c"
)
target_include_directories(p101_error_under_test PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/../../lib_error/include"
)

add_executable(test_p101_tool_event test_event.c)
target_link_libraries(test_p101_tool_event PRIVATE p101_tool_event_under_test p101_error_under_test Threads::Threads)
target_compile_options(p101_tool_event_under_test PRIVATE ${_COV})
target_compile_options(p101_error_under_test PRIVATE ${_COV})
target_compile_options(test_p101_tool_event PRIVATE ${_COV})
target_link_options(test_p101_tool_event PRIVATE ${_COV})
target_compile_definitions(test_p101_tool_event PRIVATE
        P101_TOOL_EVENT_FINGERPRINT_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/fingerprint.txt")
add_test(NAME test_p101_tool_event COMMAND test_p101_tool_event)

add_executable(test_p101_tool_event_protocol test_event_protocol.c)
target_link_libraries(test_p101_tool_event_protocol PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_protocol PRIVATE ${_COV})
target_link_options(test_p101_tool_event_protocol PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_protocol COMMAND test_p101_tool_event_protocol)

add_executable(test_p101_tool_event_summary test_summary.c)
target_link_libraries(test_p101_tool_event_summary PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_summary PRIVATE ${_COV})
target_link_options(test_p101_tool_event_summary PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_summary COMMAND test_p101_tool_event_summary)

add_executable(test_p101_tool_event_receipt test_receipt.c)
target_link_libraries(test_p101_tool_event_receipt PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_receipt PRIVATE ${_COV})
target_link_options(test_p101_tool_event_receipt PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_receipt COMMAND test_p101_tool_event_receipt)

add_executable(test_p101_tool_event_lifecycle test_lifecycle.c)
target_link_libraries(test_p101_tool_event_lifecycle PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_lifecycle PRIVATE ${_COV})
target_link_options(test_p101_tool_event_lifecycle PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_lifecycle COMMAND test_p101_tool_event_lifecycle)

add_executable(test_p101_tool_event_model test_model.c)
target_link_libraries(test_p101_tool_event_model PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_model PRIVATE ${_COV})
target_link_options(test_p101_tool_event_model PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_model COMMAND test_p101_tool_event_model)

add_executable(test_p101_tool_event_health test_health.c)
target_link_libraries(test_p101_tool_event_health PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_health PRIVATE ${_COV})
target_link_options(test_p101_tool_event_health PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_health COMMAND test_p101_tool_event_health)

add_executable(test_p101_tool_event_headers_cxx test_headers.cpp)
target_link_libraries(test_p101_tool_event_headers_cxx PRIVATE p101_tool_event_under_test p101_error_under_test)
target_compile_options(test_p101_tool_event_headers_cxx PRIVATE ${_COV})
target_link_options(test_p101_tool_event_headers_cxx PRIVATE ${_COV})
add_test(NAME test_p101_tool_event_headers_cxx COMMAND test_p101_tool_event_headers_cxx)

add_executable(p101_event_model_cli_under_test
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/model_cli.c")
target_compile_definitions(p101_event_model_cli_under_test PRIVATE P101_TOOL_EVENT_TESTING=1)
target_link_libraries(p101_event_model_cli_under_test PRIVATE
        p101_tool_event_under_test
        p101_error_under_test)
target_compile_options(p101_event_model_cli_under_test PRIVATE ${_COV})
target_link_options(p101_event_model_cli_under_test PRIVATE ${_COV})
add_test(NAME test_p101_event_model_cli
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/test_model_cli.sh"
                "$<TARGET_FILE:p101_event_model_cli_under_test>"
                "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/model-resources.log"
                "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/model-calls.log")
