cmake_minimum_required(VERSION 3.5)
set (CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

LINK_LIBRARIES(pthread m udev blkid rt)

add_executable(syncmount
main.cpp
logger_logfile.cpp
logger_console.cpp
logger_syslog.cpp
logger_mqueue.cpp
)


include_directories(
)

# host arch compile
# set(CMAKE_CXX_COMPILER g++-10)

# armhf cross compile
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++-10)
target_link_directories(syncmount PUBLIC ${PROJECT_SOURCE_DIR}/cross/lib/arm-linux-gnueabihf)

