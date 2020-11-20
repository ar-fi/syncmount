/**
 * Copyright © 2020 AR-Fi Tech Ltd. https://www.ar-fi.com
 * 
 * Project:       SyncMount
 * Filename:      log.hpp
 * Author(s):     Stanislav Silnicki
 * Licence:       GPLv3
 * 
 **/

#pragma once
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <iomanip>
#include "loggers.h"
#include <mqueue.h>

class Log
{

public:
    Log(Log &) = delete;
    Log &operator=(const Log &) = delete;

    static void Mount(const std::string &mount_path, bool read_only)
    {
        auto &instance = ImplGet();
        auto &data = instance.ImplPrepareLogData(mount_path, EventMount, read_only);
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
    static void DeInit()
    {
        ImplGet().ImplDeInit();
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
        run_deinit = false;

        if (options->contains(CONTROL_MQUEUE_NAME_OPTION))
        {
            int ret = mq_unlink(options->at(CONTROL_MQUEUE_NAME_OPTION));
        }
    }

    std::string &ImplPrepareLogData(const std::string &data, enum ImplEventType event_type, bool read_only_flag = false)
    {
        log_data.clear();
        switch (event_type)
        {
        case EventMount:

            log_data += read_only_flag ? "RO" : "RW";
            log_data += "MOUNT:";
            break;
        case EventUnmount:
            log_data += "UNMOUNT:";
            break;
        case EventError:
            log_data += "ERROR:";
            break;
        case EventInfo:
            log_data += "INFO:";
            break;
        default:
            break;
        }
        log_data += data;
        return log_data;
    };

    Log() : run_deinit(true) {}

    void ImplLog(auto &data)
    {
        auto ts = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        while (!std::strftime(ts_str.data(), ts_str.size(), "%FT%TZ", gmtime(&ts)))
            ts_str.resize(ts_str.size() + 1);

        for (auto logger : loggers)
            logger->Write(data, ts_str);
    }

    void ImplInit(const auto &options)
    {
        const time_t tmp = 0;
        while (!std::strftime(ts_str.data(), ts_str.size(), "%FT%TZ", gmtime(&tmp)))
            ts_str.resize(ts_str.size() + 1);

        loggers = {new Console, new LogFile, new Syslog, new MQueue};
        for (auto &logger : loggers)
            logger->Init(options);

        std::string info("Started with PID " + std::to_string(getpid()));
        ImplLog(info);
        this->options = &options;
    }

    static Log &ImplGet()
    {
        static Log log;
        return log;
    }

    auto &ImplGetLoggers() { return loggers; }

    std::vector<AbstractLogger *> loggers;
    std::string log_data;
    std::string ts_str;
    bool run_deinit;
    config_options_t const *options;
};
