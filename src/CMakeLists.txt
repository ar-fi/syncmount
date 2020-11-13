cmake_minimum_required(VERSION 3.5)
set (CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

LINK_LIBRARIES(pthread m udev blkid rt)

add_executable(${BINARY_FILENAME}
main.cpp
logger_logfile.cpp
logger_console.cpp
logger_syslog.cpp
logger_mqueue.cpp
)

include_directories(
)
