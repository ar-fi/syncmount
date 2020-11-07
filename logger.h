#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <map>
#include "options.h"
#include <chrono>

class AbstractLogger
{
public:
    AbstractLogger() : ready(false) {}
    AbstractLogger(const AbstractLogger &) = delete;
    AbstractLogger &operator=(const AbstractLogger &) = delete;
    bool isReady() { return ready; }
    virtual void Write(const std::string &, const std::string &) = 0;
    virtual void Init(const config_options_t &) = 0;
    virtual void DeInit() {}

protected:
    bool ready;
};

class Console : public AbstractLogger
{
public:
    void Init(const config_options_t &) override;
    void Write(const std::string &, const std::string &) override;
};

class LogFile : public AbstractLogger
{
public:
    void Init(const config_options_t &) override;
    void Write(const std::string &, const std::string &) override;

private:
    std::string filename;
};
