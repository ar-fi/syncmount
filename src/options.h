/**
 * Copyright © 2020 AR-Fi Tech Ltd. https://www.ar-fi.com
 * 
 * Project:       SyncMount
 * Filename:      options.h
 * Author(s):     Stanislav Silnicki
 * Licence:       GPLv3
 * 
 **/

#pragma once
#include <map>
#include <string>
#include <sys/stat.h>

const mode_t pid_file_mask = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
const mode_t log_file_mask = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
const mode_t mkdir_mask = (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
const mode_t event_mqueue_mask = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
const mode_t control_mqueue_mask = (S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH);

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
#define SHOW_HELP_OPTION "-h"

typedef std::map<const std::string, const char *> config_options_t;
