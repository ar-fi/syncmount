/**
 * Copyright © 2020 AR-Fi Tech Ltd. https://www.ar-fi.com
 * 
 * Project:       SyncMount
 * Filename:      logger_logfile.cpp
 * Author(s):     Stanislav Silnicki
 * Licence:       GPLv3
 * 
 **/

#include "loggers.h"

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
            log_file << ts.c_str() << ' ' << data << std::endl;
            log_file.close();
        }
    }
}
