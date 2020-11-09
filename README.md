
# USB Drives automount daemon for AR-Fi Sync solution

This piece of software is designed and implemented as a single-client daemon utility,
intended for use by its client as source of notifications about mount/unmount events.
Syncmount uses Linux kernel bindings to monitor attachment and detachment of USB mass storage devices and mounts found partitions/volumes with filesystems, supported by kernel.
The nature of tasks, run by syncmount, requires root privileges to be able to mount filesystems.


## Features:

* mounts filesystems, supported by Linux kernel (may require extra kernel modules to be installed to support particular filesystems)
* sends notifications to unprivileged piece of software by means of POSIX Message Queue
* can be used in unprivileged mode for monitoring of attached USB storage devices only
* runs in background as well as in foreground
* can mount filesystems both in read-only and read-write modes, depending on the label of partition/volume.
* can be commanded by third party software to unmount particular partition/volume by means of dedicated POSIX Message Queue

## Build 
To compile under Debian/Ubuntu:

* install build environment
```
sudo apt install git build-essential cmake libudev-dev libblkid-dev g++-10
```

* clone repository:
```
git clone https://github.com/ar-fi/syncmount
```

* cd & build
```
cd syncmount
mkdir ./build
cd ./build
cmake ../
make
```
compiled binary is in build/bin directory

## Cross-compile for armhf (Raspberry, etc) using Ubuntu host

* install build environment
```
sudo apt install git build-essential cmake libudev-dev libblkid-dev g++-10-arm-linux-gnueabihf
```

* clone repository:
```
git clone https://github.com/ar-fi/syncmount
```

* download dependency libraries (replace 'focal' for the name of your Ubuntu distro, running add-apt-repository command)
```
sudo dpkg --add-architecture armhf
sudo add-apt-repository "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports focal main multiverse restricted universe"
sudo apt update
cd ./syncmount
mkdir cross
cd ./cross
apt download libblkid1:armhf
apt download libudev1:armhf
ar x libblkid1*
unxz data.tar.xz -c | tar xf -
ar x libudev1*
unxz data.tar.xz -c | tar xf -
rm -R usr *.xz *.deb debian-binary
cd lib/arm-linux-gnueabihf
ln -s libblkid.so.1 libblkid.so
ln -s libudev.so.1 libudev.so
cd ../../../
```

* Edit src/CMakeLists.txt

comment 
```
set(CMAKE_CXX_COMPILER g++-10)
```

uncomment 
```
#set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++-10)
#target_link_directories(syncmount PUBLIC ${PROJECT_SOURCE_DIR}/cross/lib/arm-linux-gnueabihf)
```

* Compile
```
mkdir build
cd ./build
cmake ../
make
```
compiled binary is in build/bin directory

## Example usage

* to start monitor for attached partitions/volumes in foreground without mounting:
```
syncmount
```
* mount already attached USB devices, start monitor, mount and log all mounts to console and log file using default root mount path and log filename:
```
sudo syncmount -r -f -U
```
* run in background, monitor and mount ALL filesystems in ReadWrite mode, using particular root mount folder and log everything using syslog:
```
sudo -d -r /path/to/mounts -W -s
```
* run in background, mount ReadWrite all partitions/volumes, labeled 'backup' in synchronous mode, log events to syslog, default logfile (/var/log/syncmount.log) and default message queue (/syncmount.events) and control unmounts from unprivileged user space with message queue, named 'unmount_backups':
```
sudo -d -r -w backup -S -s -l -m -c /unmount_backups
```

## Usage Notice
For mounting functionality -r option as well as root privileges are required!


## Operational description

If -U option provided, on startup syncmount will search attached USB block devices and try to mount them in accordance with other command string options.

While in normal operation, syncmount monitors attachment/detachment of USB storage devices.
When USB storage attached, syncmount scans it for partitions/volumes and mount all found ones under subfolders of root mount folder as ReadOnly or ReadWrite. Mount paths will have global access for read and write for unprivileged users. 

If -w command  line option is provided, syncmount will try to match it against label of any attached partition/volume and mount the volume as Read-Write, if match was successful. If -W command line option is provided, Read-Write mount option is implied for any attached partition/volume.

If started in foreground (neither -d nor -b command line options are provided), it will log all
events to console.

If -l option provided, all events are logged into log file as well. (default: /var/log/syncmount.log)

If -m command line option is provided, syncmount will log all events into message 
queue (found in /dev/mqueue folder under Linux). The message queue name can be specified as a value for -m option. (default: /syncmount.events -> filename /dev/mqueue/syncmount.events)

If -s command line option is provided, events are logged by means of OS syslog utility.

-l -m and -s options can be used simultaneously in both foreground and background modes.
Console logging is available in foreground mode only.

-S command line option will affect all Read-Write mounts, implying sync flag and forcing OS to try all write operations with USB device synchronously.

-c command line options will create a control message queue to receive unmount command from user (default: /syncmount.control -> filename /dev/mqueue/syncmount.control)


## Runtime linkage dependencies

```
	linux-vdso.so.1 (0x00007ffcc88b9000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f4f9c789000)
	libudev.so.1 => /lib/x86_64-linux-gnu/libudev.so.1 (0x00007f4f9c75d000)
	libblkid.so.1 => /lib/x86_64-linux-gnu/libblkid.so.1 (0x00007f4f9c706000)
	librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f4f9c6fb000)
	libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f4f9c244000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f4f9c227000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4f9c035000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f4f9c7ea000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4f9c02f000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f4f9bee0000)
```

## License

GPLv3.0

## TODO

* cross-compile instructions
* pre-built packages

## Contribution

You're free to issue pull-requests, while it is not guaranteed to be revised in fixed time


