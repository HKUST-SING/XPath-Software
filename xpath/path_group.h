#ifndef __PATH_GROUP_H__
#define __PATH_GROUP_H__

#include <linux/spinlock.h>
#include <linux/ktime.h>

struct path_group_entry {
        unsigned int ecn_fraction;
        unsigned int bytes_sent;
        unsigned int bytes_ecn;
        unsigned short rate_avg;
        unsigned short rtt_avg;
        ktime_t start_time;
        spinlock_t lock;
};

bool xpath_init_path_group(struct path_group_entry *pg, unsigned int size);

#endif
