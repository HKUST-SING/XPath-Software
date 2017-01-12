#ifndef ROUTING_H
#define ROUTING_H

#include "path_table.h"
#include "path_group.h"

/* Different load balancing solutions, include:
 *      Equal-Cost Multi-Path (ECMP)
 *      Presto (SIGCOMM'15)
 *      Random Packet Spraying (INFOCOM'13)
 *      FlowBender (CoNEXT'14)
 *      LetFlow (NSDI'17)
 *      TLB (Out Solution)
 * Return IP address of desired path
 */
u32 ecmp_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 presto_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 rps_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 flowbender_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 letflow_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

u32 tlb_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr);

/* TLB related functions */
inline bool is_good_path_group(struct xpath_group_entry group);
inline bool is_gray_path_group(struct xpath_group_entry group);
u16 tlb_where_to_route(u16 current_path_index, struct xpath_path_entry *path_ptr);

#endif
