/**
 * Copyright © 2020 AR-Fi Tech Ltd. https://www.ar-fi.com
 * 
 * Project:       SyncMount
 * Filename:      main.cpp
 * Author(s):     Stanislav Silnicki
 * Licence:       GPLv3
 * 
 **/

#include <string>
#include <typeinfo>
#include <map>
#include <iostream>
#include <fstream>
#include <vector>
#include <tuple>
#include <cstdarg>
#include <cstring>
#include <sstream>
#include <memory>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libudev.h>
#include <poll.h>
#include <blkid/blkid.h>
#include <mqueue.h>
#include <functional>
#include <sys/mount.h>
#include <errno.h>
#include <sys/statvfs.h>
#include "options.h"
#include "log.hpp"
#include <regex>

using namespace std::string_literals;

#define DEFAULT_VALUE_SETTING "default"
#define HELP_STRING_SETTING "help"
#define MANDATORY_COMMAND_STRING_VALUE_FLAG "mandatory"
#define NO_VALUE_FLAG "novalue"

#define DEFAULT_ROOT_MOUNT "/var/syncmount"
#define DEFAULT_EVENTS_MQUEUE "/syncmount.events"
#define DEFAULT_CONTROL_MQUEUE "/syncmount.control"
#define DEFAULT_LOGFILE "/var/log/syncmount.log"
#define PID_FILE "/var/run/syncmount.pid"

#define MOUNT_DIR_PREFIX "syncmount_"
#define MOUNT_DIR_RND_SUFFIX_VOCAB "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define MOUNT_DIR_RND_SUFFIX_LEN (32)

const std::regex MOUNT_DIR_NAME_RE("/" MOUNT_DIR_PREFIX "[" MOUNT_DIR_RND_SUFFIX_VOCAB "]+$");

#define SUPPRESS_LOGGING (true)
#define DONT_SUPPRESS_LOGGING (false)

// const std::regex r(""s + MOUNT_DIR_PREFIX +  );

const std::map<const std::string, const config_options_t> OPTIONS = {
    {ROOT_MOUNT_OPTION,
     {{DEFAULT_VALUE_SETTING, DEFAULT_ROOT_MOUNT}, {HELP_STRING_SETTING, "Root mount path."}}},
    {EVENTS_MQUEUE_NAME_OPTION, {{NO_VALUE_FLAG, ""}, {DEFAULT_VALUE_SETTING, DEFAULT_EVENTS_MQUEUE}, {HELP_STRING_SETTING, "Events mesage queue name."}}},
    {CONTROL_MQUEUE_NAME_OPTION, {{NO_VALUE_FLAG, ""}, {DEFAULT_VALUE_SETTING, DEFAULT_CONTROL_MQUEUE}, {HELP_STRING_SETTING, "Control mesage queue name."}}},
    {LOG_FILE_OPTION, {{DEFAULT_VALUE_SETTING, DEFAULT_LOGFILE}, {HELP_STRING_SETTING, "Log filename."}}},
    {RW_LABEL_OPTION, {{MANDATORY_COMMAND_STRING_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Disk/partition/volume label for RW mount."}}},
    {USE_SYSLOG_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Use syslog for logging."}}},
    {ALWAYS_RW_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Mount RW everything."}}},
    {SYNC_MOUNT_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Apply sync flag when mounting RW."}}},
    {RUN_BACKGROUND_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Run in background (aka -d)."}}},
    {DAEMONIZE_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Daemonize (aka -b)."}}},
    {SHOW_HELP_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Show these clues."}}},
    {SCAN_FOR_USB_DEVICES_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "On start scan for existing USB partitions and mount them."}}},
};

const std::map<const std::string, const std::string> filesystem_specific_mount_options = {
    {"vfat", "iocharset=utf8,umask=0"},
    {"ntfs", "umask=0"},
};

int main(const int argc, const char *argv[])
{
    // lifetime vars
    config_options_t command_string_options;
    std::string root_mount_path;
    std::map<std::string, std::pair<std::string, bool>> mounted_paths;
    int abort_ret_code = 0;

    // signals handler
    struct sigaction child_sigaction = {0};
    child_sigaction.sa_flags = SA_NOCLDWAIT; // suppress zombie creations
    child_sigaction.sa_sigaction = [](int s, siginfo_t *info, void *arg) {
        (void)arg;
        if (s == SIGHUP)
            Log::SuppressDeinit();

        Log::Info("Stopped PID "s + std::to_string(getpid()) + " by signal "s + std::to_string(s));
        Log::DeInit();

        _exit(0); // terminate process
    };

    for (int i = 1; i <= 64; i++)
        sigaction(i, &child_sigaction, NULL);

    // lambda
    auto is_key = [](auto &key_candidate) {
        return OPTIONS.contains(key_candidate);
    };

    // lambda
    auto has_default = [](auto &key) {
        return OPTIONS.contains(key) && OPTIONS.at(key).contains(DEFAULT_VALUE_SETTING);
    };

    // lambda
    auto novalue_option = [&is_key](auto &key) {
        return OPTIONS.contains(key) && OPTIONS.at(key).contains(NO_VALUE_FLAG);
    };

    // lambda
    auto get_default_value = [&is_key](auto &key) {
        return is_key(key) ? (OPTIONS.at(key).contains(DEFAULT_VALUE_SETTING) ? OPTIONS.at(key).at(DEFAULT_VALUE_SETTING) : nullptr) : nullptr;
    };

    // lambda
    auto is_mandatory = [&is_key](auto &key) {
        return is_key(key) ? OPTIONS.at(key).contains(MANDATORY_COMMAND_STRING_VALUE_FLAG) : false;
    };

    // lambda
    auto verify_mandatory = [&is_key](auto &key, auto &... value) {
        try
        {
            if constexpr (!sizeof...(value))
            {
                throw std::exception();
            }
            else
            {
                if (is_key(value...))
                    throw std::exception();
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "ERROR: Value for '" << key << "' option ("
                      << OPTIONS.at(key).at(HELP_STRING_SETTING)
                      << ") must be explicitly specified!" << std::endl
                      << std::flush;
            throw std::exception();
        }
    };

    // lambda
    auto append_option = [&command_string_options](const auto &key, const auto &value) {
        if (command_string_options.contains(key) && !OPTIONS.at(key).contains(NO_VALUE_FLAG))
        {
            std::cerr << "ERROR: Option '" << key
                      << "' specified more than once!" << std::endl
                      << std::flush;
            throw std::exception();
        }
        command_string_options[key] = value;
    };

    // parse command string for options
    try
    {
        abort_ret_code++;
        for (int i = 1; i < argc; i++)
        {
            if (!is_key(argv[i]))
            {
                std::cerr << "ERROR: Unknow option '" << argv[i] << "'" << std::endl
                          << std::flush;
                throw std::exception();
            }

            if ((i + 1) >= argc) // last command line option
            {
                if (is_mandatory(argv[i]))
                    verify_mandatory(argv[i]);

                append_option(argv[i], get_default_value(argv[i]));
            }
            else
            {
                if (is_mandatory(argv[i]))
                    verify_mandatory(argv[i], argv[i + 1]);

                if (is_key(argv[i + 1]) || novalue_option(argv[i]))
                    append_option(argv[i], get_default_value(argv[i]));
                else
                {
                    if (has_default(argv[i]) || !novalue_option(argv[i]))
                    {
                        append_option(argv[i], argv[i + 1]);
                        i++; // skip found value for this key
                    }
                }
            }
        }

        abort_ret_code++;
        // root mount path sanity check
        if (command_string_options.contains(ROOT_MOUNT_OPTION))
        {

            if (getuid() != 0)
            {
                std::cerr << "ERROR: -r option requires root privileges" << std::endl
                          << std::flush;
                throw std::exception();
            }

            root_mount_path = std::string(command_string_options.at(ROOT_MOUNT_OPTION));
            if (root_mount_path.at(0) != '/')
            {
                std::cerr << "ERROR: -r option requires absolute path, staring with '/'" << std::endl
                          << std::flush;
                throw std::exception();
            }

            if (root_mount_path.find("//"s) != std::string::npos || root_mount_path.find("/.."s) != std::string::npos || root_mount_path.find("/./"s) != std::string::npos || root_mount_path.starts_with("/dev/"s))
            {
                std::cerr << "ERROR: Can't create path, specified for -r option: '" << root_mount_path << "'" << std::endl
                          << std::flush;
                throw std::exception();
            }

            if (root_mount_path.length() > (PATH_MAX - NAME_MAX - strlen("RWMOUNT:")))
            {
                std::cerr << "ERROR: too long path name for -r option" << std::endl
                          << std::flush;
                throw std::exception();
            }
            if (root_mount_path.length() < 2)
            {
                std::cerr << "ERROR: too short path name for -r option" << std::endl
                          << std::flush;
                throw std::exception();
            }

            // try create required root mount path
            if (root_mount_path.back() == '/')
                root_mount_path.pop_back();

            umask(~mkdir_mask & 0777);
            int search_pos = 0;
            do
            {
                search_pos = root_mount_path.find('/', search_pos + 1);
                if (mkdir(root_mount_path.substr(0, search_pos).c_str(), mkdir_mask) < 0)
                {
                    if (errno != EEXIST)
                    {
                        std::cerr << "ERROR: Can't create path, specified for -r option: '" << root_mount_path << "'" << std::endl
                                  << std::flush;
                        throw std::exception();
                    }
                }
            } while (search_pos != std::string::npos);

            root_mount_path.push_back('/');
        }
    }
    catch (const std::exception &e)
    {
        return abort_ret_code; // terminate if command string options parsing failed
    }

    // show help clues
    if (command_string_options.contains(SHOW_HELP_OPTION))
    {
        std::cerr << R"(
    USB mass storage automount/monitoring utility.

    syncmount [options]

    Options:)" << std::endl;

        for (const auto option : OPTIONS)
        {
            const auto &[key, settings] = option;
            const bool mandatory_string_value = settings.contains(MANDATORY_COMMAND_STRING_VALUE_FLAG);
            const bool novalue = settings.contains(NO_VALUE_FLAG);
            const auto &default_value = settings.contains(DEFAULT_VALUE_SETTING) ? settings.at(DEFAULT_VALUE_SETTING) : std::string();
            const auto &help_string = settings.at(HELP_STRING_SETTING);

            std::cerr << "\t" << key << "\t - " << help_string;
            if (novalue)
                std::cerr << " No value required.";
            else
                std::cerr << " String value required.";
            if (default_value.size())
            {
                std::cerr << std::endl
                          << "\t\t\t"
                          << "Default: " << default_value;
            }
            std::cerr << std::endl
                      << std::endl;
        }
        return 0;
    }

    // cleanup previous start
    std::ifstream pid_file(PID_FILE, std::ios::in | std::ios::binary | std::ios::ate);
    if (pid_file.is_open())
    {
        if (pid_file.tellg()) // non zero pid file
        {
            std::string pid_data;
            pid_data.resize(pid_file.tellg());
            pid_data.reserve(pid_file.tellg());
            pid_file.seekg(std::ios::beg);
            pid_file.read(pid_data.data(), pid_data.size());
            pid_t pid = std::strtoul(pid_data.c_str(), NULL, 10);
            if (pid) // pid parsed w/o errors
                kill(pid, SIGHUP);
        }
        pid_file.close();
        unlink(PID_FILE);
    }

    // initialise loggers
    try
    {
        abort_ret_code++;
        Log::Init(command_string_options);
    }
    catch (const std::exception &e)
    {
        return abort_ret_code;
    }

    // initialise usb monitor
    struct udev *const udev_handle = udev_new();
    struct udev_monitor *const udev_monitor_handle = udev_monitor_new_from_netlink(udev_handle, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(udev_monitor_handle, "block", "disk");
    udev_monitor_enable_receiving(udev_monitor_handle);

    struct pollfd pfds[2] = {0}; // usb monitor + unmount control
    const int poll_fds = 2;

    struct pollfd *const monitor = &pfds[0];
    monitor->fd = udev_monitor_get_fd(udev_monitor_handle);
    abort_ret_code++;
    if (monitor->fd < 0)
    {
        std::cerr << "ERROR: Can't utilize UDEV kernel infrastructure." << std::endl
                  << std::flush;
        return abort_ret_code;
    }
    else
        monitor->events = POLLIN;

    // add userspace controller
    struct pollfd *const control = &pfds[1];
    if (command_string_options.contains(CONTROL_MQUEUE_NAME_OPTION))
    {
        mq_attr attr = {0};
        attr.mq_maxmsg = 16;
        attr.mq_msgsize = MQUEUE_MESSAGE_SIZE; // unmount control message will contain path of the mount
        umask(~control_mqueue_mask & 0777);
        control->fd = mq_open(command_string_options.at(CONTROL_MQUEUE_NAME_OPTION), O_CREAT | O_RDONLY, control_mqueue_mask, &attr);
        if (control->fd < 0)
            Log::Info("Can't create control message queue. Unmount control is unavailable.");
        else
            control->events = POLLIN;
    }
    else
        control->fd = -1; // negative fd is ignored by poll

    // fork if required
    abort_ret_code++;
    if (command_string_options.contains(RUN_BACKGROUND_OPTION) || command_string_options.contains(DAEMONIZE_OPTION))
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            std::cerr << "ERROR: Can't daemonise." << std::endl
                      << std::flush;
            return abort_ret_code;
        }
        else if (pid > 0)
        {
            //parent: write pid file and exit
            std::ofstream pid_file(PID_FILE, std::ios::out | std::ios::trunc);
            if (pid_file.is_open())
            {
                std::string pid_data = std::to_string(pid);
                pid_file.write(pid_data.data(), pid_data.size());
                pid_file.flush();
                pid_file.close();
            }
            return 0;
        }
        else
        {
            // child
            fclose(stderr);
            fclose(stdin);
            fclose(stdout);
            setsid();
        }
    }

    // lambda
    auto generate_mount_dir_name = []() {
        srand(std::chrono::system_clock::now().time_since_epoch().count());
        std::string dir_name(MOUNT_DIR_PREFIX);
        for (int i = 0; i < MOUNT_DIR_RND_SUFFIX_LEN; i++)
            dir_name.push_back(MOUNT_DIR_RND_SUFFIX_VOCAB[(uint64_t)rand() * (strlen(MOUNT_DIR_RND_SUFFIX_VOCAB) - 1) / RAND_MAX]);
        return dir_name;
    };

    // lambda
    auto mount_fs = [&command_string_options, &mounted_paths](const auto &mount_path, const auto &device, const auto &label, const auto &type, bool suppress_logging) {
        try
        {
            umask(~mkdir_mask & 0777);
            if (mkdir(mount_path.c_str(), mkdir_mask) < 0 && errno != EEXIST)
            {
                if (!suppress_logging)
                    Log::Error("Can't create mount directory.");
                throw std::exception();
            }

            unsigned long mount_flags = MS_RDONLY | MS_NOATIME | MS_NODEV | MS_NODIRATIME | MS_NOEXEC | MS_NOSUID;

            if (command_string_options.contains(ALWAYS_RW_OPTION) || (command_string_options.contains(RW_LABEL_OPTION) && !label.compare(std::string(command_string_options.at(RW_LABEL_OPTION)))))
            {
                mount_flags &= ~MS_RDONLY;
                if (chmod(mount_path.c_str(), 0777) < 0)
                {
                    if (!suppress_logging)
                        Log::Error("Can't change permissions for mount directory.");
                    throw std::exception();
                }
            }
            if (command_string_options.contains(SYNC_MOUNT_OPTION))
                mount_flags |= MS_SYNCHRONOUS;

            if (mount(device.c_str(), mount_path.c_str(), type.c_str(), mount_flags,
                      filesystem_specific_mount_options.contains(type) ? filesystem_specific_mount_options.at(type).c_str() : nullptr) == 0) // great! it has been mounted
            {
                struct statvfs stat = {0};
                statvfs(mount_path.c_str(), &stat);

                mounted_paths[mount_path] = std::pair<std::string, bool>(device, stat.f_flag & MS_RDONLY);
                if (!suppress_logging)
                    Log::Mount(mount_path, stat.f_flag & MS_RDONLY);

                if (!(mount_flags & MS_RDONLY) && (stat.f_flag & MS_RDONLY))
                {
                    if (!suppress_logging)
                        Log::Info("Can mount " + type + " filesystem in read-only mode only.");
                }
            }
            else // something went wrong
            {
                switch (errno)
                {
                case EACCES: //
                {
                    if (!(mount_flags & MS_RDONLY))
                    {
                        if (!suppress_logging)
                            Log::Error("Can't mount read-only filesystem in write mode.");
                    }
                    else
                    {
                        if (!suppress_logging)
                            Log::Error("Internal error while mounting filesystem: " + std::to_string(errno));
                    }
                }
                break;
                case ENODEV:
                {
                    if (!suppress_logging)
                        Log::Error("Filesystem "s + type + " is not supported by this kernel.");
                }
                break;
                default:
                {
                    if (!suppress_logging)
                        Log::Error("Internal error while mounting filesystem: " + std::to_string(errno));
                }
                break;
                }
                throw std::exception();
            }
        }
        catch (const std::exception &e)
        {
            rmdir(mount_path.c_str());
            return;
        }
    };

    // lambda
    std::function<void(const std::string &, bool)> // recursion requires explicit prototype
        probe_device = [&](const std::string &dev_name, bool suppress_logging) {
            const blkid_probe pr = blkid_new_probe_from_filename(dev_name.c_str());
            if (!pr)
                return;
            blkid_probe_enable_partitions(pr, 1);
            blkid_do_safeprobe(pr);

            blkid_partlist ls;
            int nparts;

            ls = blkid_probe_get_partitions(pr);
            if (ls && (nparts = blkid_partlist_numof_partitions(ls)) != 0)
            {
                for (int i = 0; i < nparts; i++)
                    probe_device(dev_name + std::to_string(i + 1), suppress_logging);
            }
            else
            {
                const char *fs_uuid;
                const char *fs_label;
                const char *fs_type;
                size_t fs_uuid_len = 0;
                size_t fs_label_len = 0;
                size_t fs_type_len = 0;

                int err = 0;
                err += blkid_probe_lookup_value(pr, "UUID", &fs_uuid, &fs_uuid_len);
                err += blkid_probe_lookup_value(pr, "LABEL", &fs_label, &fs_label_len);
                err += blkid_probe_lookup_value(pr, "TYPE", &fs_type, &fs_type_len);

                if (err)
                {
                    if (!suppress_logging)
                        Log::Error("Probe of "s + dev_name + " falied.");
                }
                else if (root_mount_path.size())
                {
                    std::string dir_name;
                    do
                    {
                        dir_name = generate_mount_dir_name();
                    } while (mounted_paths.contains(dir_name));
                    mount_fs(root_mount_path + dir_name, dev_name, std::string(fs_label), std::string(fs_type), suppress_logging);
                }
                else
                {
                    if (!suppress_logging)
                        Log::Info("New device with "s + fs_type + " filesystem, labeled as '" + fs_label + "'");
                }
            }
            blkid_free_probe(pr);
        };

    // lambda
    auto remove_device = [&mounted_paths](const auto &removed_device) {
        std::vector<std::string> unmounted;
        for (const auto &[mount_path, data] : mounted_paths)
        {
            const auto &[mounted_device, read_only] = data;
            if (mounted_device.starts_with(removed_device))
            {
                umount2(mount_path.c_str(), MNT_DETACH);
                unmounted.push_back(mount_path);
                rmdir(mount_path.c_str());
                Log::Umount(mount_path);
            }
        }
        for (const auto &path : unmounted)
            mounted_paths.erase(path);
    };

    { // tmp scope
        std::vector<std::string> mounted_devices;

        // build a list of already mounted filesystems
        std::fstream proc_mounts("/proc/mounts", std::ios::in);
        if (proc_mounts.is_open())
        {
            std::string mount_line;
            std::regex r("^([^\\s]+)\\s+([^\\s]+)\\s+[^\\s]+\\s+r([ow])");
            std::smatch m;
            while (std::getline(proc_mounts, mount_line))
            {
                if (std::regex_search(mount_line, m, r))
                {
                    std::string device = m.str(1);
                    std::string mount_path = m.str(2);

                    std::string::size_type pos = 0u;
                    while ((pos = mount_path.find("\\040", pos)) != std::string::npos)
                    {
                        mount_path.replace(pos, 4, " ");
                        pos += 1;
                    }
                    bool read_only_mount = m.str(3).starts_with("o");
                    mounted_devices.push_back(device);

                    if (std::regex_search(mount_path, m, MOUNT_DIR_NAME_RE))
                        mounted_paths[mount_path] = std::pair<std::string, bool>(device, read_only_mount);
                }
            }
            proc_mounts.close();
        }

        // force rescan USB mass storage devices and mount unmounted partitions
        if (command_string_options.contains(SCAN_FOR_USB_DEVICES_OPTION))
        {
            struct udev_enumerate *udev_enum = udev_enumerate_new(udev_handle);
            udev_enumerate_add_match_subsystem(udev_enum, "block");
            udev_enumerate_add_match_property(udev_enum, "ID_BUS", "usb");
            udev_enumerate_scan_devices(udev_enum);

            struct udev_list_entry *dev_list = udev_enumerate_get_list_entry(udev_enum);

            while (dev_list)
            {
                udev_device *current_device = udev_device_new_from_syspath(udev_handle, udev_list_entry_get_name(dev_list));
                const std::string device_path((udev_list_entry_get_value(udev_list_entry_get_by_name(udev_device_get_properties_list_entry(current_device), "DEVNAME"))));
                udev_device_unref(current_device);

                if (std::find_if(mounted_devices.begin(), mounted_devices.end(),
                                 [&](const auto &obj) {
                                     return !obj.compare(device_path);
                                 }) == mounted_devices.end())
                    probe_device(device_path, SUPPRESS_LOGGING);
                dev_list = udev_list_entry_get_next(dev_list);
            }
            udev_enumerate_unref(udev_enum);
        }
    } // tmp scope

    struct udev_device *current_device;
    abort_ret_code++;

    // main event loop
    while (true)
    {
        monitor->revents = control->revents = 0;
        if (poll(pfds, poll_fds, -1) <= 0)
        {
            Log::Error("Internal error");
            return abort_ret_code;
        }

        if (control->revents & POLLIN)
        {
            char buffer[MQUEUE_MESSAGE_SIZE];
            int read_bytes = mq_receive(control->fd, buffer, sizeof(buffer), 0);

            int path_len = 0;
            while (path_len < read_bytes && buffer[path_len]) // search zero terminated C string
                path_len++;

            if (path_len)
            {
                std::string path(buffer, path_len);
                if (mounted_paths.contains(path))
                    remove_device(mounted_paths.at(path).first);
            }
        }

        if (monitor->revents & POLLIN && (current_device = udev_monitor_receive_device(udev_monitor_handle)) != nullptr)
        {
            const std::string device_action(udev_device_get_action(current_device));
            const std::string device_path((udev_list_entry_get_value(udev_list_entry_get_by_name(udev_device_get_properties_list_entry(current_device), "DEVNAME"))));

            if (device_action == "add")
                probe_device(device_path, DONT_SUPPRESS_LOGGING);
            else if (device_action == "remove")
                remove_device(device_path);

            udev_device_unref(current_device);
        }
    }

    return 0;
}
