cmake_minimum_required(VERSION 3.5)
set (CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

link_directories(
)

add_executable(syncmount
    main.cpp
    logger_logfile.cpp
    logger_console.cpp
    log.hpp
    )

TARGET_LINK_LIBRARIES(syncmount pthread m udev blkid rt crypto)

include_directories(
)
