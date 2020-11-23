cmake_minimum_required(VERSION 3.5)

project(syncmount)

#build stuff

set(REQUIRED_COMPILER_VER 10)

SET(CMAKE_C_COMPILER /usr/bin/$ENV{DEB_HOST_GNU_TYPE}-gcc-${REQUIRED_COMPILER_VER})
SET(CMAKE_CXX_COMPILER /usr/bin/$ENV{DEB_HOST_GNU_TYPE}-g++-${REQUIRED_COMPILER_VER})

SET(BINARY_FILENAME syncmount-$ENV{DEB_HOST_GNU_TYPE})

add_subdirectory(src bin)

SET(CMAKE_FIND_ROOT_PATH /usr/$ENV{DEB_HOST_GNU_TYPE})
SET(ONLY_CMAKE_FIND_ROOT_PATH TRUE)
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


# package stuff

install(PROGRAMS 
build/bin/${BINARY_FILENAME}
DESTINATION "/usr/sbin/"
RENAME "syncmount"
)

install(PROGRAMS 
${PROJECT_SOURCE_DIR}/init/syncmount
DESTINATION "/etc/init.d"
)

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${PROJECT_SOURCE_DIR}/init/prerm;${PROJECT_SOURCE_DIR}/init/postinst")

SET(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE $ENV{DEB_TARGET_ARCH})
SET(CPACK_PACKAGE_NAME "Syncmount")
SET(CPACK_PACKAGE_VENDOR "AR-Fi Tech")

SET(CPACK_PACKAGE_VERSION_MAJOR 1)
SET(CPACK_PACKAGE_VERSION_MINOR 0)
SET(CPACK_PACKAGE_VERSION_PATCH 5)

SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "dev@ar-fi.com")

SET(CPACK_DEBIAN_PACKAGE_HOMEPAGE https://github.com/ar-fi/syncmount)
SET(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)

SET(CPACK_DEBIAN_PACKAGE_SECTION utils)

SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libudev1, libblkid1, libc6, libstdc++6")
# set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

SET(CPACK_DEBIAN_PACKAGE_CONFLICTS 
usbmount
)

SET(CPACK_PACKAGE_DESCRIPTION "This piece of software is designed and implemented as a single-client daemon utility,
intended for use by its client as source of notifications about mount/unmount events.
Syncmount uses Linux kernel bindings to monitor attachment and detachment of USB mass storage devices and mounts found partitions/volumes with filesystems, supported by kernel.
The nature of tasks, run by syncmount, requires root privileges to be able to mount filesystems.")

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "USB automount daemon for AR-Fi Sync")

INCLUDE(CPack)

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package)
