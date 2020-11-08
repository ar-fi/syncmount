/**
 * Copyright © 2020 AR-Fi Tech Ltd. https://www.ar-fi.com
 * 
 * Project:       SyncMount
 * Filename:      logger_mqueue.cpp
 * Author(s):     Stanislav Silnicki
 * Licence:       GPLv3
 * 
 **/

#include "loggers.h"
#include <mqueue.h>
#include <errno.h>

void MQueue::Init(const config_options_t &options)
{
    if (options.contains(EVENTS_MQUEUE_NAME_OPTION))
    {
        mq_attr attr = {0};
        attr.mq_maxmsg = 16;
        attr.mq_msgsize = MQUEUE_MESSAGE_SIZE; // unmount control message will contain path of the mount
        umask(~events_mqueue_mask & 0777);

        mq_fd = mq_open(options.at(EVENTS_MQUEUE_NAME_OPTION), O_CREAT | O_WRONLY, events_mqueue_mask, &attr);
        if (mq_fd < 0)
        {
            std::cerr << "ERROR: Can't create events message queue: " << errno << std::endl;
            throw std::exception();
        }
        mqueue_name = options.at(EVENTS_MQUEUE_NAME_OPTION);
        ready = true;
    }
}

void MQueue::Write(const std::string &data, const std::string &ts)
{
    if (ready)
    {
        mq_send(mq_fd, data.data(), data.size(), 0);
    }
}

void MQueue::DeInit()
{
    if (mq_fd > 0)
    {
        mq_close(mq_fd);
        mq_unlink(mqueue_name.c_str());
    }
}
