#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <vector>
#include <tuple>
#include <cstdarg>
#include <sstream>
#include <memory>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace std::string_literals;

#define DEFAULT_VALUE_SETTING "default"
#define HELP_STRING_SETTING "help"
#define MANDATORY_COMMAND_STRING_VALUE_FLAG "mandatory"
#define NO_VALUE_FLAG "novalue"

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

#define DEFAULT_ROOT_MOUNT "/var/syncmount"
#define DEFAULT_EVENTS_MQUEUE "/syncmount.events"
#define DEFAULT_CONTROL_MQUEUE "/syncmount.control"
#define DEFAULT_LOGFILE "/var/log/syncmount.log"
#define PID_FILE "syncmount.pid"

typedef std::map<const std::string, const char *> option_settings_t;
const std::map<const std::string, const option_settings_t> OPTIONS = {
    {ROOT_MOUNT_OPTION,
     {{DEFAULT_VALUE_SETTING, DEFAULT_ROOT_MOUNT}, {HELP_STRING_SETTING, "Root mount path"}}},
    {EVENTS_MQUEUE_NAME_OPTION, {{DEFAULT_VALUE_SETTING, DEFAULT_EVENTS_MQUEUE}, {HELP_STRING_SETTING, "Events mesage queue name"}}},
    {CONTROL_MQUEUE_NAME_OPTION, {{DEFAULT_VALUE_SETTING, DEFAULT_CONTROL_MQUEUE}, {HELP_STRING_SETTING, "Control mesage queue name"}}},
    {LOG_FILE_OPTION, {{DEFAULT_VALUE_SETTING, DEFAULT_LOGFILE}, {HELP_STRING_SETTING, "Log filename"}}},
    {RW_LABEL_OPTION, {{MANDATORY_COMMAND_STRING_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Disk/partition/volume label for RW mount"}}},
    {USE_SYSLOG_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Use syslog for logging"}}},
    {ALWAYS_RW_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Mount RW everything"}}},
    {SYNC_MOUNT_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Apply sync flag when mounting RW"}}},
    {RUN_BACKGROUND_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Run in background (aka -d)"}}},
    {DAEMONIZE_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Daemonize (aka -b)"}}},
};

typedef std::map<const std::string, const char *> command_string_options_t;

void print_map(const auto &map)
{
    const auto print_key_value = [&](const auto &data) {
        // const auto &[key, auto &[defaul, help]] = data;
        const auto &[key, value] = data;
        std::cout << key << " -> " << (value ? value : "") << std::endl;
    };
    for_each(begin(map), end(map), print_key_value);
}

class AbstractLogger
{
public:
    AbstractLogger() : ready(false) {}
    AbstractLogger(const AbstractLogger &) = delete;
    AbstractLogger &operator=(const AbstractLogger &) = delete;
    bool isReady() { return ready; }
    virtual void Write(const std::string &) = 0;
    virtual void Init(const command_string_options_t &) = 0;
    virtual void DeInit() = 0;

protected:
    bool ready;
};

class Console : public AbstractLogger
{
public:
    Console() {}
    void Init(const command_string_options_t &options) override
    {
        if (!options.contains(RUN_BACKGROUND_OPTION) && !options.contains(DAEMONIZE_OPTION))
            ready = true;
    }
    void DeInit() override {} // console doesn't need any

    void Write(const std::string &data) override
    {
        if (ready)
            std::cerr << data << std::endl
                      << std::flush;
    }
};

class Log
{

public:
    Log(Log &) = delete;
    Log &operator=(const Log &) = delete;

    static void Mount(const std::string &mount_path, bool write_mount)
    {
        auto &instance = ImplGet();
        auto &data = instance.ImplPrepareLogData(mount_path, EventMount, write_mount);
        instance.ImplLog(data);
    }
    static void Umount(const std::string &mount_path)
    {
        auto &instance = ImplGet();
        auto &data = instance.ImplPrepareLogData(mount_path, EventUnmount);
        instance.ImplLog(data);
    }
    static void Error(const std::string &what)
    {
        auto &instance = ImplGet();
        auto &data = instance.ImplPrepareLogData(what, EventError);
        instance.ImplLog(data);
    }
    static void Info(const std::string &what)
    {
        auto &instance = ImplGet();
        auto &data = instance.ImplPrepareLogData(what, EventInfo);
        instance.ImplLog(data);
    }
    static void Init(const auto &options)
    {
        ImplGet().ImplInit(options);
    }

    static void SuppressDeinit()
    {
        ImplGet().run_deinit = false; // suppress when stopped by particular signal
    }

    ~Log()
    {
        if (run_deinit)
            ImplDeInit();
    }

private:
    enum ImplEventType
    {
        EventMount,
        EventUnmount,
        EventError,
        EventInfo
    };

    void ImplDeInit()
    {
        for (auto logger : loggers)
            logger->DeInit();
    }

    std::string &ImplPrepareLogData(const std::string &data, enum ImplEventType event_type, bool write_mount_flag = false)
    {
        log_data.clear();
        std::stringstream ss;
        switch (event_type)
        {
        case EventMount:
            ss << "MOUNT:" << (write_mount_flag ? "RW" : "RD") << ":";
            break;
        case EventUnmount:
            ss << "UNMOUNT:";
            break;
        case EventError:
            ss << "ERROR:";
            break;
        case EventInfo:
            ss << "INFO:";
            break;
        default:
            break;
        }
        ss << data;
        log_data = ss.str();
        return log_data;
    };

    Log() : run_deinit(true) {}

    void ImplLog(auto &data)
    {
        for (auto logger : loggers)
            logger->Write(data);
    }

    void ImplInit(const auto &options)
    {
        loggers = {new Console};
        for (auto &logger : loggers)
            logger->Init(options);
    }

    static Log &ImplGet()
    {
        static Log log;
        return log;
    }

    auto &ImplGetLoggers() { return loggers; }

    std::vector<AbstractLogger *> loggers;
    std::string log_data;
    bool run_deinit;
};

int main(const int argc, const char *argv[])
{
    umask(~(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) & 0777);

    struct sigaction child_sigaction = {0};
    child_sigaction.sa_flags = SA_NOCLDWAIT; // suppress zombie creations
    child_sigaction.sa_sigaction = [](int s, siginfo_t *info, void *arg) {
        (void)arg;
        if (s == SIGHUP)
            Log::SuppressDeinit();
        Log::Info("Stopped by signal "s + std::to_string(s));
        _exit(0); // terminate process
    };

    for (int i = 1; i <= 64; i++)
        sigaction(i, &child_sigaction, NULL);

    // cleanup
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

    // parse command string for options
    command_string_options_t options;

    auto is_key = [](auto &key_candidate) {
        return OPTIONS.contains(key_candidate);
    };

    auto has_default = [](auto &key) {
        return OPTIONS.contains(key) && OPTIONS.at(key).contains(DEFAULT_VALUE_SETTING);
    };

    auto novalue_option = [&is_key](auto &key) {
        return OPTIONS.contains(key) && OPTIONS.at(key).contains(NO_VALUE_FLAG);
    };

    auto get_default_value = [&is_key](auto &key) {
        return is_key(key) ? (OPTIONS.at(key).contains(DEFAULT_VALUE_SETTING) ? OPTIONS.at(key).at(DEFAULT_VALUE_SETTING) : nullptr) : nullptr;
    };

    auto is_mandatory = [&is_key](auto &key) {
        return is_key(key) ? OPTIONS.at(key).contains(MANDATORY_COMMAND_STRING_VALUE_FLAG) : false;
    };

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

    auto append_option = [&options](const auto &key, const auto &value) {
        if (options.contains(key) && !OPTIONS.at(key).contains(NO_VALUE_FLAG))
        {
            std::cerr << "ERROR: Option '" << key
                      << "' specified more than once!" << std::endl
                      << std::flush;
            throw std::exception();
        }
        options[key] = value;
    };

    try
    {
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

                if (is_key(argv[i + 1]))
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
    }
    catch (const std::exception &e)
    {
        return 1; // terminate with error if command string options parsing failed
    }

    // fork if required
    if (options.contains(RUN_BACKGROUND_OPTION) || options.contains(DAEMONIZE_OPTION))
    {
        try
        {
            pid_t pid = fork();
            if (pid < 0)
                throw std::exception();
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
                while (true)
                    sleep(1);
            }
        }
        catch (const std::exception &e)
        {
            return 2;
        }
    }

    // print_map(options);

    Log::Init(options);

    return 0;
}
