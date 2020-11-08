cmake_minimum_required(VERSION 3.5)
set (CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_COMPILER g++-10)

link_directories(
)

add_executable(syncmount
    main.cpp
    logger_logfile.cpp
    logger_console.cpp
    logger_syslog.cpp
    logger_mqueue.cpp
    )

TARGET_LINK_LIBRARIES(syncmount pthread m udev blkid rt crypto)

include_directories(
)
