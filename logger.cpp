
#include "logger.h"

Console::Console() {}
void Console::Init(const config_options_t &options)
{
    if (!options.contains(RUN_BACKGROUND_OPTION) && !options.contains(DAEMONIZE_OPTION))
        ready = true;
}
void Console::DeInit()
{
}

void Console::Write(const std::string &data)
{
    if (ready)
        std::cerr << data << std::endl
                  << std::flush;
}
