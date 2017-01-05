#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>

#include "routing.h"
#include "flow_table.h"
#include "path_group.h"
#include "net_util.h"
#include "params.h"

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u16 num_cong_rtts;
	u16 reroute;
};

/* Flow Table */
extern struct xpath_flow_table ft;
/* Path Table */
extern struct xpath_path_table pt;
/* Path Group */
extern struct xpath_group_entry pg[XPATH_PATH_GROUP_SIZE];

u32 ecmp_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph = tcp_hdr(skb);
        u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
					     iph->daddr,
					     tcph->source,
					     tcph->dest);
        /* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
        u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 presto_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph = tcp_hdr(skb);
        u32 payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
        u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
		                             iph->daddr,
					     tcph->source,
                                             tcph->dest);
        /* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
        u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

        xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
        f.info.path_index = path_index;

        if (tcph->syn && unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC))) {
                if (xpath_enable_debug)
                        printk(KERN_INFO "XPath: insert flow fails\n");

        } else if ((tcph->fin || tcph->rst) && !xpath_delete_flow_table(&ft, &f)) {
                if (xpath_enable_debug)
                        printk(KERN_INFO "XPath: delete flow fails\n");

        } else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f))) {
                path_index = flow_ptr->info.path_index;
		/* exceed flowcell threshold */
                if (flow_ptr->info.bytes_sent + payload_len > xpath_flowcell_thresh) {
                        flow_ptr->info.bytes_sent = payload_len;
                        if (++path_index >= path_ptr->num_paths)
                                path_index -= path_ptr->num_paths;
                        flow_ptr->info.path_index = path_index;
                } else {
                        flow_ptr->info.bytes_sent += payload_len;
                }
        }

        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 rps_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        u32 path_index = (u32)atomic_inc_return(&path_ptr->current_path);
	path_index = path_index % path_ptr->num_paths;
        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 flowbender_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph = tcp_hdr(skb);
        struct dctcp *ca = inet_csk_ca(skb->sk);
	u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
		                             iph->daddr,
					     tcph->source,
                                             tcph->dest);
        /* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
        u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;

        if (likely(ca)) {
                path_index = (path_index + ca->reroute) % path_ptr->num_paths;
                if (xpath_enable_debug)
                        printk(KERN_INFO "Reroute %hu\n", ca->reroute);
        }

        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 tlb_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
	unsigned long tmp;
	ktime_t now = ktime_get();
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	//u32 payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
					     iph->daddr,
					     tcph->source,
					     tcph->dest);

	/* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
	u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

	xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
	f.info.path_index = path_index;

	if (tcph->syn) {
		f.info.last_tx_time = now;
		f.info.last_reroute_time = now;
                /* insert a new flow entry to the flow table */
                if (unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC))) {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: insert flow fails\n");
                }
	} else if (tcph->fin || tcph->rst) {
		if (!xpath_delete_flow_table(&ft, &f)) {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: delete flow fails\n");
		}
	} else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f))) {
		/* idenfity a flowlet and reroute*/
		if (ktime_to_us(ktime_sub(now, flow_ptr->info.last_tx_time)) >
		    xpath_flowlet_thresh) {
			path_index = flow_ptr->info.path_index;
			if (++path_index >= path_ptr->num_paths)
				path_index = 0;
			flow_ptr->info.path_index = path_index;
			flow_ptr->info.num_flowlet++;
			flow_ptr->info.last_reroute_time = now;
			flow_ptr->info.bytes_sent = skb->len;
		} else {
			flow_ptr->info.bytes_sent += skb->len;
		}
		flow_ptr->info.last_tx_time = now;
	}

	/* Get path IP based on path index */
	return path_ptr->path_ips[path_index];
}

static inline bool is_good_path_group(struct xpath_group_entry group)
{
	return group.ecn_fraction < xpath_tlb_ecn_low_thresh &&
	       group.smooth_rtt_us < xpath_tlb_rtt_low_thresh;
}

static inline bool is_gray_path_group(struct xpath_group_entry group)
{
	return  group.ecn_fraction < xpath_tlb_ecn_low_thresh ||
	        group.smooth_rtt_us < xpath_tlb_rtt_low_thresh;
}

/*
 * where_to_route() of tlb load balancing algorithm
 * return desired path index
 */
static u16 tlb_where_to_route(u16 current_path_index, struct xpath_path_entry *path_ptr)
{
	u16 i, path_index = current_path_index;
	unsigned int path_group_id;
	u16 min_rate_mbps = 65535;	/* maximum value = 2^16 - 1 */

	/* select a good path with the smallest sending rate */
	for (i = 0; i < path_ptr->num_paths; i++) {
		path_group_id = path_ptr->path_group_ids[i];
		if (path_group_id < XPATH_PATH_GROUP_SIZE &&
		    is_good_path_group(pg[path_group_id]) &&
	    	    pg[path_group_id].rate_mbps < min_rate_mbps) {
                	path_index = i;
			min_rate_mbps = pg[path_group_id].rate_mbps;
		}
	}

	/* if a good path exists */
	if (path_index != current_path_index)
		goto out;

	/* select a gray path with the smallest sending rate */
	for (i = 0; i < path_ptr->num_paths; i++) {
		path_group_id = path_ptr->path_group_ids[i];
		if (path_group_id < XPATH_PATH_GROUP_SIZE &&
		    is_gray_path_group(pg[path_group_id]) &&
	    	    pg[path_group_id].rate_mbps < min_rate_mbps) {
                	path_index = i;
			min_rate_mbps = pg[path_group_id].rate_mbps;
		}
	}

out:
        return path_index;
}
