/**
 * Copyright © 2020 AR-Fi Tech Ltd. https://www.ar-fi.com
 * 
 * Project:       SyncMount
 * Filename:      logger_console.cpp
 * Author(s):     Stanislav Silnicki
 * Licence:       GPLv3
 * 
 **/

#include "loggers.h"

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
