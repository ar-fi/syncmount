#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <map>
#include <sstream>
#include "options.h"

class AbstractLogger
{
public:
    AbstractLogger() : ready(false) {}
    AbstractLogger(const AbstractLogger &) = delete;
    AbstractLogger &operator=(const AbstractLogger &) = delete;
    bool isReady() { return ready; }
    virtual void Write(const std::string &) = 0;
    virtual void Init(const config_options_t &) = 0;
    virtual void DeInit() = 0;

protected:
    bool ready;
};

class Console : public AbstractLogger
{
public:
    Console();
    void Init(const config_options_t &options) override;
    void DeInit() override;
    void Write(const std::string &data) override;
};
