#ifndef __NET_UTIL_H__
#define __NET_UTIL_H__

#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netdevice.h>

/* add ECT and modify DSCP for IP header */
void xpath_modify_ip_header(struct iphdr *iph, u32 payload_len);

/* Modify TCP MSS option in SYN packets */
bool xpath_reduce_tcp_mss(struct sk_buff *skb, unsigned short int reduce_size);

/* IPIP encapsulation */
bool xpath_ipip_encap(struct sk_buff *skb,
                      struct iphdr *tiph,
                      const struct net_device *out);

/* IPIP decapsulation */
bool xpath_ipip_decap(struct sk_buff *skb);

/* Compute flow hash key by crc16 */
unsigned short xpath_flow_hash_crc16(unsigned int local_ip,
                                     unsigned int remote_ip,
                                     unsigned short local_port,
                                     unsigned short remote_port);

#endif
