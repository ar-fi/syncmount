
#include "logger.h"
#include <fstream>
#include <chrono>

void Console::Init(const config_options_t &options)
{
    if (!options.contains(RUN_BACKGROUND_OPTION) && !options.contains(DAEMONIZE_OPTION))
        ready = true;
}

void Console::Write(const std::string &data, const std::string &ts)
{
    if (ready)
        std::cerr << data << std::endl
                  << std::flush;
}

void LogFile::Init(const config_options_t &options)
{
    if (options.contains(LOG_FILE_OPTION))
    {
        umask(~log_file_mask & 0777);
        std::fstream log_file(options.at(LOG_FILE_OPTION), std::fstream::out | std::fstream::app);
        if (log_file.is_open())
        {
            log_file.close();
            filename = options.at(LOG_FILE_OPTION);
            ready = true;
        }
    }
}

void LogFile::Write(const std::string &data, const std::string &ts)
{
    if (ready)
    {
        umask(~log_file_mask & 0777);
        std::fstream log_file(filename, std::fstream::out | std::fstream::app);
        if (log_file.is_open())
        {
            log_file << ts << ' ' << data << std::endl;
            log_file.close();
        }
    }
}
