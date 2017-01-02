#ifndef __PATH_GROUP_H__
#define __PATH_GROUP_H__

#include <linux/spinlock.h>
#include <linux/ktime.h>

/* A path group consists of multiple paths from the same server to the same ToR switch */
struct xpath_group_entry {
        /* ECN information */
        u16 ecn_fraction;       //ECN fraction of all flows (maximum 1024)
        u32 bytes_acked;        //bytes ACKed in this path group
        u32 bytes_ecn;  //bytes get ECN marked in this path group
        ktime_t last_ecn_update_time;   //last time when we update ECN statistic

        /* RTT information */
        u16 smooth_rtt_us;      //smooth RTT in microsecond of this path group
        ktime_t last_rtt_update_time;   //last time when we update RTT information

        /* sending rate information */
        u32 bytes_sent; //bytes sent in this path group
        u16 rate_mbps;  //sending rate in Mbps
        ktime_t last_rate_update_time;   //last time when we update rate information

        spinlock_t lock;
};

bool xpath_init_path_group(struct xpath_group_entry *pg, unsigned int size);

#endif
