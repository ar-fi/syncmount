
# USB Drives automount daemon for AR-Fi Sync solution

This piece of software is designed and implemented as a single-client daemon utility,
intended for use by its client as source of notifications about mount/unmount events.
Syncmount uses Linux kernel bindings to monitor attachement and detachement of USB mass storage devices and mounts found partitions/volumes with filesystems, supported by kernel.
The nature of tasks, run by syncmount, requires root priveledges to be able to mount filesystems.

## Features:

* mounts filesystems, supported by Linux kernel (may require extra kernel modules to be installed to support particular filesystems)
* sends notification to unpreviledged piece of software by means of POSIX Message Queue
* can be used in unpriveledged mode for monitoring of attached USB storage devices only
* runs in background as well as in foregroud
* can mount filesystems both in read-only and read-write modes, depending on the label of partition/volume.
* can be commanded by third party software to unmount particular partition/volume by means of dedicated POSIX Message Queue

## Build

To compile under Debian/Ununtu:

* install bulid environment
```
sudo apt install git build-essential cmake libudev-dev libblkid-dev libssl-dev g++-10
```

* clone repo:
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

## Example usage

* to start monitor for attached partitions/volumes in foreground without mounting:
```
syncmount
```
* start monitor, mount and log all mounts to console and log file using default root mount path and log filename:
```
sudo syncmount -r -f
```
* run in background, monitor and mount ALL filesystems in ReadWrite mode, using particular root mount folder and log everything usdin syslog:
```
sudo -d -r /path/to/mounts -W -s
```
* run in background, mount ReadWrite all partitions/volumes, labeled 'backup' in synchronous mode, log events to syslog, default logfile (/var/log/syncmount.log) and default message queue (/syncmount.events) and control unmounts from unpreveledged user space with message queue, named 'unmount_backups':
```
sudo -d -r -w backup -S -s -l -m -c /unmount_backups
```


## Operational description

While in normal operation, syncmount monitors attachement/detachement of USB storage devices.
When USB storage attached, syncmount scans it for partitions/volumes and mount all found ones under subfolders of root mount folder as ReadOnly or ReadWrite. Mount paths will have global access for read and write for unpriveledged users. 

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
	libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f4f9c425000)
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

* scan and account already mounted partitions/volumes upon startup (option)
* mount attached USB partitions/volumes upon startup (option)
* cross-compile instructions
* prebuilt packages

## Contribution

You're free to issue pull-requests, while it is not guaranteed to be revised in 