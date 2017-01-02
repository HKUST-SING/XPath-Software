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
        /* hash_key_space = 1 << 16; path_id = hash_key * path_ptr->num_paths / region_size; */
        u32 path_id = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
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
        /* hash_key_space = 1 << 16; path_id = hash_key * path_ptr->num_paths / region_size; */
        u32 path_id = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

        xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
        f.info.path_group_id = path_id;

        if (tcph->syn && unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC))) {
                if (xpath_enable_debug)
                        printk(KERN_INFO "XPath: insert flow fails\n");

        } else if ((tcph->fin || tcph->rst) && !xpath_delete_flow_table(&ft, &f)) {
                if (xpath_enable_debug)
                        printk(KERN_INFO "XPath: delete flow fails\n");

        } else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f))) {
                path_id = flow_ptr->info.path_group_id;
                if (flow_ptr->info.bytes_sent + payload_len > xpath_flowcell_thresh) {
                        flow_ptr->info.bytes_sent = payload_len;
                        if (++path_id >= path_ptr->num_paths)
                                path_id -= path_ptr->num_paths;
                        flow_ptr->info.path_group_id = path_id;
                } else {
                        flow_ptr->info.bytes_sent += payload_len;
                }
        }

        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
}

u32 rps_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        unsigned int path_id = (unsigned int)atomic_inc_return(&path_ptr->current_path);
        path_id = path_id % path_ptr->num_paths;

        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
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
        /* hash_key_space = 1 << 16; path_id = hash_key * path_ptr->num_paths / region_size; */
        u32 path_id = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;

        if (likely(ca)) {
                path_id = (path_id + ca->reroute) % path_ptr->num_paths;
                if (xpath_enable_debug)
                        printk(KERN_INFO "Reroute %hu\n", ca->reroute);
        }

        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
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
	/* hash_key_space = 1 << 16; path_id = hash_key * path_ptr->num_paths / region_size; */
	u32 path_id = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

	xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
	f.info.path_group_id = path_id;

	if (tcph->syn) {
		f.info.last_tx_time = now;
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
	}

	/* Get path IP from path ID */
	return path_ptr->path_ips[path_id];
}
