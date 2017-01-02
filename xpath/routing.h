#ifndef ROUTING_H
#define ROUTING_H

#include "path_table.h"

/* Different load balancing solutions, include:
 *      Equal-Cost Multi-Path (ECMP)
 *      Presto (SIGCOMM'15)
 *      Random Packet Spraying (INFOCOM'13)
 *      FlowBender (CoNEXT'14)
 *      TLB (Out Solution)
 * Return IP address of desired path
 */
u32 ecmp_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 presto_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 rps_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 flowbender_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 tlb_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

#endif
