#include <string>
#include <map>
#include <iostream>
#include <vector>
#include <tuple>
#include <cstdarg>
using namespace std::string_literals;

#define DEFAULT_VALUE_SETTING "default"
#define HELP_STRING_SETTING "help"
#define MANDATORY_COMMAND_STRING_VALUE_FLAG "mandatory"
#define NO_VALUE_FLAG "novalue"

#define ROOT_MOUNT_OPTION "-r"
#define MQUEUE_NAME_OPTION "-m"
#define LOG_FILE_OPTION "-l"
#define RW_LABEL_OPTION "-w"
#define ALWAYS_RW_OPTION "-W"
#define SYNC_MOUNT_OPTION "-S"
#define USE_SYSLOG_OPTION "-s"
#define DAEMONIZE_OPTION "-d"
#define RUN_BACKGROUND_OPTION "-b"

#define DEFAULT_ROOT_MOUNT "/var/syncmount"
#define DEFAULT_MQUEUE "/syncmount"
#define DEFAULT_LOGFILE "/var/log/syncmount.log"

typedef std::map<const std::string, const char *> option_settings_t;
const std::map<const std::string, const option_settings_t> OPTIONS = {
    {ROOT_MOUNT_OPTION,
     {{DEFAULT_VALUE_SETTING, DEFAULT_ROOT_MOUNT}, {HELP_STRING_SETTING, "Root mount path"}}},
    {MQUEUE_NAME_OPTION, {{DEFAULT_VALUE_SETTING, DEFAULT_MQUEUE}, {HELP_STRING_SETTING, "Mesage queue name"}}},
    {LOG_FILE_OPTION, {{DEFAULT_VALUE_SETTING, DEFAULT_LOGFILE}, {HELP_STRING_SETTING, "Log filename"}}},
    {RW_LABEL_OPTION, {{MANDATORY_COMMAND_STRING_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Disk/partition/volume label for RW mount"}}},
    {USE_SYSLOG_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Use syslog for logging"}}},
    {ALWAYS_RW_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Mount RW everything"}}},
    {SYNC_MOUNT_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Apply sync flag when mounting RW"}}},
    {RUN_BACKGROUND_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Run in background (aka -d)"}}},
    {DAEMONIZE_OPTION, {{NO_VALUE_FLAG, ""}, {HELP_STRING_SETTING, "Daemonize (aka -b)"}}},
};

void print_map(const auto &map)
{
    const auto print_key_value = [&](const auto &data) {
        // const auto &[key, auto &[defaul, help]] = data;
        const auto &[key, value] = data;
        std::cout << key << " -> " << (value ? value : "") << std::endl;
    };
    for_each(begin(map), end(map), print_key_value);
}

class Log
{

public:
    Log(Log &) = delete;
    Log &operator=(const Log &) = delete;

    static void Mount(const std::string &mount_path, bool w);
    static void Umount(const std::string &mount_path);
    static void Error(const std::string &what);
    static void Setup(const auto &options)
    {
        ImplGet().ImplSetup(options);
    }

private:
    Log() : use_stderr(true), use_logfile(false), use_syslog(false), use_mqueue(false){};

    void ImplSetup(const auto &options)
    {
        use_stderr = !options.contains(RUN_BACKGROUND_OPTION) && !options.contains(DAEMONIZE_OPTION);
        use_logfile = options.contains(LOG_FILE_OPTION);
        use_syslog = options.contains(USE_SYSLOG_OPTION);
        use_mqueue = options.contains(MQUEUE_NAME_OPTION);
    }

    static Log &ImplGet()
    {
        static Log log;
        return log;
    }

    bool use_syslog;
    bool use_mqueue;
    bool use_logfile;
    bool use_stderr;
    const std::string log_file;
    const std::string mqueue_name;
};

typedef std::map<const std::string, const char *> command_string_options_t;

int main(const int argc, const char *argv[])
{
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

    print_map(options);

    Log::Setup(options);

    return 0;
}
