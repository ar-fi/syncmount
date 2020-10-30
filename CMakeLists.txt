cmake_minimum_required(VERSION 3.5)
set (CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

link_directories(
)

add_executable(syncmount
    main.cpp
    )

TARGET_LINK_LIBRARIES(syncmount pthread m)


include_directories(
)
