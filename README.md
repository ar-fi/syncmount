USB Drives automount daemon for AR-Fi Sync solution

This piece of software is designed and implemented as a single-client daemon utility,
used by its client as source for mount/unmount events.

The nature of tasks, run by syncmount, requires root priveledges.

While in normal operation, syncmount monitors attachement/detachement of USB storage devices.
Uhen attached, it scans for partitions/volumes and mount all found ones under
subfolders of root mount folder (-r command line option) as ReadOnly. If -w command 
line option is provided, syncmount will try to match it arainst label of any attached partition/volume
and mount the volume as Read-Write if successful. If -W command line option is provided,
Read-Write mount option is implied.

Syncmount can run in background as well as foreground.
If started in foreground (neither -d nor -b command line options are provided), it will log all
events to console.
If -l option provided, all events are logged into log file as well.
If -m command line option is provided, syncmount will log all events into log file into message 
queue (found in /dev/mqueue folder under Linux). The message queue name can be specified. 
If -s command line option is provided, events are logged by means of OS syslog utility.

-l -m and -s options can be used independantly in both foreground and background modes.

The queued message (-m command line option) has the following format:

        uint8_t mount_type (0 - ReadOnly, 1 - ReadWrite)
        char[] path (NULL-terminated string with full mount path)

