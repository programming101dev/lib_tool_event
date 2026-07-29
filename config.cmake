# Project metadata
set(PROJECT_NAME "p101_tool_event")
set(PROJECT_VERSION "0.0.1")
set(PROJECT_DESCRIPTION "Programming 101 event protocol and lifecycle model")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        -Werror
)

set(DARWIN_STANDARD_FLAGS
        -D_DARWIN_C_SOURCE
)

set(LINUX_STANDARD_FLAGS)
set(BSD_STANDARD_FLAGS)

set(LIBRARY_TARGETS p101_tool_event)

set(p101_tool_event_SOURCES
        src/event.c
        src/lifecycle.c
        src/ownership.c
        src/receipt.c
        src/summary.c
)

set(p101_tool_event_HEADERS
        include/p101_tool_event/event.h
        include/p101_tool_event/lifecycle.h
        include/p101_tool_event/ownership.h
        include/p101_tool_event/receipt.h
        include/p101_tool_event/summary.h
)

set(p101_tool_event_LINK_LIBRARIES
        p101_error
)
