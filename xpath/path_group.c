#include "path_group.h"

bool xpath_init_path_group(struct path_group_entry *pg, unsigned int size)
{
        int i;

        if (!pg || size <= 0)
                return false;

        for (i = 0; i < size; i++) {
                pg[i].ecn_fraction = 0;
                pg[i].bytes_sent = 0;
                pg[i].bytes_ecn = 0;
                pg[i].rate_avg = 0;
                pg[i].rtt_avg = 0;
                pg[i].start_time = ktime_set(0, 0);
                spin_lock_init(&(pg[i].lock));
        }

        return true;
}
