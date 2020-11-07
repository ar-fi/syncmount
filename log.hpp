#pragma once
#include <string>
#include <map>
#include <vector>
#include "logger.h"
#include <sstream>
#include <chrono>
#include <iomanip>

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

    std::string &ImplPrepareLogData(const std::string &data, enum ImplEventType event_type, bool read_only_flag = false)
    {
        log_data.clear();
        std::stringstream ss;
        switch (event_type)
        {
        case EventMount:
            ss << (read_only_flag ? "RO" : "RW") << "MOUNT:";
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
        auto ts = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::ostringstream ss;
        ss << std::put_time(gmtime(&ts), "%FT%TZ");
        for (auto logger : loggers)
            logger->Write(data, ss.str());
    }

    void ImplInit(const auto &options)
    {
        loggers = {new Console, new LogFile};
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
