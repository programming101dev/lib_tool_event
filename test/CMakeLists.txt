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
add_compile_definitions(_POSIX_C_SOURCE=200809L)

option(P101_TEST_COVERAGE "Instrument the code under test" OFF)
set(P101_COVERAGE_FLAGS "")
if(P101_TEST_COVERAGE)
    set(P101_COVERAGE_FLAGS --coverage)
endif()

set(P101_PUBLIC_INCLUDE_DIRS "" CACHE STRING "Extra p101 include dirs")
set(P101_PUBLIC_LINK_DIRS "" CACHE STRING "Extra p101 link dirs")
separate_arguments(P101_PUBLIC_INCLUDE_DIRS_LIST NATIVE_COMMAND "${P101_PUBLIC_INCLUDE_DIRS}")
separate_arguments(P101_PUBLIC_LINK_DIRS_LIST NATIVE_COMMAND "${P101_PUBLIC_LINK_DIRS}")
foreach(library IN ITEMS ERROR)
    string(TOLOWER "${library}" library_name)
    find_library(P101_${library}_LIBRARY NAMES p101_${library_name} PATHS ${P101_PUBLIC_LINK_DIRS_LIST} NO_DEFAULT_PATH)
    if(NOT P101_${library}_LIBRARY)
        find_library(P101_${library}_LIBRARY NAMES p101_${library_name})
    endif()
    if(NOT P101_${library}_LIBRARY)
        message(FATAL_ERROR "Could not find p101_${library_name}")
    endif()
endforeach()

add_library(p101_record_under_test STATIC
        ../../lib_record/src/event_write.c
        ../../lib_record/src/record.c)
target_include_directories(p101_record_under_test PUBLIC
        ../../lib_record/include)
target_compile_definitions(p101_record_under_test PRIVATE P101_RECORD_TESTING=1)
target_compile_options(p101_record_under_test PRIVATE ${P101_COVERAGE_FLAGS})

add_library(p101_transition_under_test STATIC ../../lib_transition/src/transition.c)
target_include_directories(p101_transition_under_test PUBLIC ../../lib_transition/include)
target_compile_options(p101_transition_under_test PRIVATE ${P101_COVERAGE_FLAGS})

add_library(p101_json_under_test STATIC ../../lib_json/src/json.c)
target_include_directories(p101_json_under_test PUBLIC
        ../../lib_json/include
        ../../lib_error/include)
target_compile_definitions(p101_json_under_test PRIVATE P101_JSON_TESTING=1)
target_compile_options(p101_json_under_test PRIVATE ${P101_COVERAGE_FLAGS})
target_link_libraries(p101_json_under_test PUBLIC ${P101_ERROR_LIBRARY})

add_library(p101_tool_support_under_test STATIC
        ../../lib_tool_support/src/diagnostic.c
        ../../lib_tool_support/src/lesson_catalog.c
        ../../lib_tool_support/src/receipt.c
        ../../lib_tool_support/src/report.c)
target_include_directories(p101_tool_support_under_test PUBLIC
        ../../lib_tool_support/include)
target_compile_options(p101_tool_support_under_test PRIVATE ${P101_COVERAGE_FLAGS})
target_link_libraries(p101_tool_support_under_test PUBLIC
        ${P101_ERROR_LIBRARY}
        p101_json_under_test
        p101_record_under_test)

add_library(p101_tool_event_under_test STATIC
        ../src/analysis.c
        ../src/event.c
        ../src/lifecycle.c
        ../src/model.c
        ../src/model_input.c
        ../src/model_json.c
        ../src/ownership.c
        ../src/summary.c)
target_include_directories(p101_tool_event_under_test PUBLIC
        ../include
        ${P101_PUBLIC_INCLUDE_DIRS_LIST})
target_compile_definitions(p101_tool_event_under_test PRIVATE P101_TOOL_EVENT_TESTING=1)
target_compile_options(p101_tool_event_under_test PRIVATE ${P101_COVERAGE_FLAGS})
target_link_libraries(p101_tool_event_under_test PUBLIC
        ${P101_ERROR_LIBRARY}
        p101_json_under_test
        p101_record_under_test
        p101_transition_under_test
        p101_tool_support_under_test
        Threads::Threads)

configure_file(fixtures/fingerprint.txt fingerprint.txt COPYONLY)

foreach(test_name IN ITEMS event event_protocol health lifecycle model summary)
    add_executable(test_${test_name} test_${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE p101_tool_event_under_test)
    target_compile_options(test_${test_name} PRIVATE ${P101_COVERAGE_FLAGS})
    target_link_options(test_${test_name} PRIVATE ${P101_COVERAGE_FLAGS})
    add_test(NAME test_${test_name} COMMAND test_${test_name})
endforeach()

add_executable(test_headers_cxx test_headers.cpp)
target_link_libraries(test_headers_cxx PRIVATE p101_tool_event_under_test)
target_compile_options(test_headers_cxx PRIVATE ${P101_COVERAGE_FLAGS})
target_link_options(test_headers_cxx PRIVATE ${P101_COVERAGE_FLAGS})
add_test(NAME test_headers_cxx COMMAND test_headers_cxx)

add_executable(p101_event_model_cli_under_test ../src/model_cli.c)
target_compile_definitions(p101_event_model_cli_under_test PRIVATE P101_TOOL_EVENT_TESTING=1)
target_link_libraries(p101_event_model_cli_under_test PRIVATE p101_tool_event_under_test)
target_compile_options(p101_event_model_cli_under_test PRIVATE ${P101_COVERAGE_FLAGS})
target_link_options(p101_event_model_cli_under_test PRIVATE ${P101_COVERAGE_FLAGS})
add_test(NAME test_model_cli
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/test_model_cli.sh"
                "$<TARGET_FILE:p101_event_model_cli_under_test>"
                "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/model-resources.log"
                "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/model-calls.log")

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    foreach(library IN ITEMS p101_record_under_test p101_transition_under_test p101_json_under_test p101_tool_support_under_test)
        target_compile_options(${library} PRIVATE -Wall -Wextra -Werror -pedantic-errors)
    endforeach()
    target_compile_options(p101_tool_event_under_test PRIVATE -Wall -Wextra -Werror -pedantic-errors)
    foreach(test_name IN ITEMS event event_protocol health lifecycle model summary)
        target_compile_options(test_${test_name} PRIVATE -Wall -Wextra -Werror -pedantic-errors)
    endforeach()
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(test_headers_cxx PRIVATE -Wall -Wextra -Werror -pedantic-errors)
endif()
