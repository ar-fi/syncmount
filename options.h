#pragma once
#include <map>
#include <string>

#define ROOT_MOUNT_OPTION "-r"
#define EVENTS_MQUEUE_NAME_OPTION "-m"
#define CONTROL_MQUEUE_NAME_OPTION "-c"
#define LOG_FILE_OPTION "-l"
#define RW_LABEL_OPTION "-w"
#define ALWAYS_RW_OPTION "-W"
#define SYNC_MOUNT_OPTION "-S"
#define USE_SYSLOG_OPTION "-s"
#define DAEMONIZE_OPTION "-d"
#define RUN_BACKGROUND_OPTION "-b"

typedef std::map<const std::string, const char *> config_options_t;
