#include "loggers.h"
#include <syslog.h>

void Syslog::Init(const config_options_t &options)
{
    if (options.contains(USE_SYSLOG_OPTION))
    {
        openlog("syncmount", LOG_ODELAY, LOG_USER);
        ready = true;
    }
}

void Syslog::Write(const std::string &data, const std::string &ts)
{
    if (ready)
        syslog(LOG_INFO, "%s", data.c_str());
}

void Syslog::DeInit()
{
    if (ready)
        closelog();
}
