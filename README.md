USB Drives automount daemon for AR-Fi Sync solution

This piece of software is designed and implemented as a single-client daemon utility,
used by its client as source for notifications about mount/unmount events.

The nature of tasks, run by syncmount, requires root priveledges.

While in normal operation, syncmount monitors attachement/detachement of USB storage devices.
When USB storage attached, it scans for partitions/volumes and mount all found ones under
subfolders of root mount folder (-r command line option) as ReadOnly. If -w command 
line option is provided, syncmount will try to match it against label of any attached partition/volume and mount the volume as Read-Write if match was successful.If -W command line option is provided, Read-Write mount option is implied for any USB device.

Syncmount can run in background as well as foreground.
If started in foreground (neither -d nor -b command line options are provided), it will log all
events to console.
If -l option provided, all events are logged into log file as well.
If -m command line option is provided, syncmount will log all events into message 
queue (found in /dev/mqueue folder under Linux). The message queue name can be specified as a value for -m option. 
If -s command line option is provided, events are logged by means of OS syslog utility.

-l -m and -s options can be used simultaneously in both foreground and background modes.

-S command line option will affect all Read-Write mounts, implying sync flag and forcing OS to try all read/write operations with USB device synchronously.

-c command line options will create a control message queue to receive unmount command from user
