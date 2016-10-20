#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>

#include "netfilter.h"
#include "flow_table.h"
#include "xpath_table.h"
#include "net_util.h"
#include "params.h"

/* borrow from codel_time_after in include/net/codel.h of Linux kernel */
#define seq_after(a, b)						\
	(typecheck(u32, a) &&					\
	 typecheck(u32, b) &&					\
	 ((s32)((a) - (b)) > 0))

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
/* NIC device name */
extern char *param_dev;
/* TCP port */
extern int param_port;

/* Netfilter hook for outgoing packets */
static struct nf_hook_ops xpath_nf_hook_out;
/* Netfilter hook for incoming packets */
static struct nf_hook_ops xpath_nf_hook_in;

/* Return desired path IP based on load balancing mechanisms */
static u32 ecmp_routing(const struct sk_buff *skb,
                        struct xpath_path_entry *path_ptr);
static u32 presto_routing(const struct sk_buff *skb,
			  struct xpath_path_entry *path_ptr);
static u32 rps_routing(const struct sk_buff *skb,
                       struct xpath_path_entry *path_ptr);
static u32 flowbender_routing(const struct sk_buff *skb,
                              struct xpath_path_entry *path_ptr);
static u32 tlb_routing(const struct sk_buff *skb,
		       struct xpath_path_entry *path_ptr);

static u32 ecmp_routing(const struct sk_buff *skb,
                        struct xpath_path_entry *path_ptr)
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

static u32 presto_routing(const struct sk_buff *skb,
                          struct xpath_path_entry *path_ptr)
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
        f.info.path_id = path_id;

        if (tcph->syn)
        {
                /* insert a new flow entry to the flow table */
                if (unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC)))
                {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: insert flow fails\n");
                }
        }
        else if (tcph->fin || tcph->rst)
        {
                if (!xpath_delete_flow_table(&ft, &f))
                {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: delete flow fails\n");
                }
        }
        else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f)))
        {
                path_id = flow_ptr->info.path_id;
                if (flow_ptr->info.bytes_sent + payload_len > xpath_flowcell_thresh)
                {
                        flow_ptr->info.bytes_sent = payload_len;
                        if (++path_id >= path_ptr->num_paths)
                                path_id -= path_ptr->num_paths;
                        flow_ptr->info.path_id = path_id;
                }
                else
                {
                        flow_ptr->info.bytes_sent += payload_len;
                }
        }

        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
}

static u32 rps_routing(const struct sk_buff *skb,
                       struct xpath_path_entry *path_ptr)
{
        unsigned int path_id = (unsigned int)atomic_inc_return(&path_ptr->current_path);
        path_id = path_id % path_ptr->num_paths;

        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
}

static u32 flowbender_routing(const struct sk_buff *skb,
                              struct xpath_path_entry *path_ptr)
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

        if (likely(ca))
        {
                path_id = (path_id + ca->reroute) % path_ptr->num_paths;
                if (xpath_enable_debug)
                        printk(KERN_INFO "Reroute %hu\n", ca->reroute);
        }

        /* Get path IP from path ID */
        return path_ptr->path_ips[path_id];
}

static u32 tlb_routing(const struct sk_buff *skb,
		       struct xpath_path_entry *path_ptr)
{
	u64 ecn_fraction;
	unsigned long tmp;
	ktime_t start_time, now = ktime_get();
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
	f.info.path_id = path_id;

	if (tcph->syn)
	{
		f.info.seq = ntohl(tcph->seq);
		f.info.last_tx_time = ktime_get();

                /* insert a new flow entry to the flow table */
                if (unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC)))
                {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: insert flow fails\n");
                }
	}
	else if (tcph->fin || tcph->rst)
	{
		if (!xpath_delete_flow_table(&ft, &f))
		{
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: delete flow fails\n");
		}
	}
	else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f)))
	{
		start_time = flow_ptr->info.ecn_start_time;
		/* not yet start a ECN measurement cycle */
		if (start_time.tv64 == 0)
			goto out;

		/* cannot finish current ECN measurement cycle */
		if (ktime_us_delta(now, start_time) < xpath_tlb_ecn_sample_us ||
		    flow_ptr->info.bytes_acked_total < xpath_tlb_ecn_sample_bytes)
		    	goto out;

		ecn_fraction = flow_ptr->info.bytes_acked_ecn << 10;
		do_div(ecn_fraction, max(1U, flow_ptr->info.bytes_acked_total));
		flow_ptr->info.ecn_fraction = min((u32)ecn_fraction, 1024U);

		spin_lock_irqsave(&(flow_ptr->lock), tmp);
		flow_ptr->info.bytes_acked_ecn = 0;
		flow_ptr->info.bytes_acked_total = 0;
		spin_unlock_irqrestore(&(flow_ptr->lock), tmp);

		/* trigger next measurement cycle */
		flow_ptr->info.ecn_start_time = ktime_set(0, 0);

		/* reset measurement results */
		if (xpath_enable_debug)
			printk(KERN_INFO "ECN fraction %u\n", flow_ptr->info.ecn_fraction);

		if (flow_ptr->info.ecn_fraction < xpath_tlb_ecn_fraction)
			goto out;

		path_id = flow_ptr->info.path_id;
		if (++path_id >= path_ptr->num_paths)
			path_id -= path_ptr->num_paths;
		flow_ptr->info.path_id = path_id;
	}

out:
	/* Get path IP from path ID */
	return path_ptr->path_ips[path_id];
}

/* Hook function for outgoing packets */
static unsigned int xpath_hook_func_out(const struct nf_hook_ops *ops,
                                        struct sk_buff *skb,
                                        const struct net_device *in,
                                        const struct net_device *out,
                                        int (*okfn)(struct sk_buff *))
{
        struct iphdr *iph = ip_hdr(skb);
        struct iphdr tiph;  /* tunnel (outer) IP header */
        struct tcphdr *tcph;
        struct xpath_path_entry *path_ptr = NULL;
        u32 path_ip = 0;    /* IP address of the path */

        if (likely(out) && param_dev && strncmp(out->name, param_dev, IFNAMSIZ) != 0)
                return NF_ACCEPT;

        /* we only filter TCP packets */
        if (likely(iph) && iph->protocol == IPPROTO_TCP)
        {
                tcph = tcp_hdr(skb);
                if (param_port != 0 &&
                    ntohs(tcph->source) != param_port &&
                    ntohs(tcph->dest) != param_port)
                        return NF_ACCEPT;

                path_ptr = xpath_search_path_table(&pt, iph->daddr);
                /* cannot find path information */
                if (unlikely(!path_ptr || path_ptr->num_paths == 0))
                {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: cannot find path\n");

                        return NF_DROP;
                }

                /* Reduce MSS value in SYN packets */
                if (tcph->syn &&
                    unlikely(!xpath_reduce_tcp_mss(skb, sizeof(struct iphdr))))
                {
                        if (xpath_enable_debug)
                                printk(KERN_INFO "XPath: cannot modify MSS\n");

                        return NF_DROP;
                }


		switch (xpath_load_balancing)
		{
			case ECMP:
				path_ip = ecmp_routing(skb, path_ptr);
				break;
			case PRESTO:
				path_ip = presto_routing(skb, path_ptr);
				break;
			case RPS:
                        	path_ip = rps_routing(skb, path_ptr);
                        	break;
			case FLOWBENDER:
				path_ip = flowbender_routing(skb, path_ptr);
				break;
			case TLB:
				path_ip = tlb_routing(skb, path_ptr);
				break;
			default:
				printk(KERN_INFO "XPath: unknown LB scheme %d\n",
                                                 xpath_load_balancing);
		}

                /* construct tunnel (outer) IP header */
		if (likely(path_ip > 0))
		{
                        tiph.version = 4;
                        tiph.ihl = sizeof(struct iphdr) >> 2;
                        tiph.tot_len =  htons(ntohs(iph->tot_len) + \
                                        sizeof(struct iphdr));
                        tiph.id = iph->id;
                        tiph.frag_off = iph->frag_off;
                        tiph.protocol = IPPROTO_IPIP;
                        tiph.tos = iph->tos;
                        tiph.daddr = path_ip;
                        tiph.saddr = iph->saddr;
                        tiph.ttl = iph->ttl;

                        /* ECN capable (to avoid switch bug) */
                        if (!INET_ECN_is_capable(tiph.tos))
                                tiph.tos |= INET_ECN_ECT_0;

                        tiph.check = 0;
                        tiph.check = ip_fast_csum(&tiph, tiph.ihl);
                }
		else
		{
			if (xpath_enable_debug)
				printk(KERN_INFO "Xpath: invalid path IP\n");

			return NF_DROP;
		}

                /* add tunnel (outer) IP header */
                if (unlikely(!xpath_ipip_encap(skb, &tiph, out)))
                {
			if (xpath_enable_debug)
                        	printk(KERN_INFO "XPath: cannot add IP header\n");

			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

/* Hook function for incoming packets */
static unsigned int xpath_hook_func_in(const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct xpath_flow_entry f, *flow_ptr = NULL;
	u32 bytes_acked;
	unsigned long tmp;

	if (likely(in) && param_dev && strncmp(in->name, param_dev, IFNAMSIZ) != 0)
                goto out;

	if (unlikely(!iph) || iph->protocol != IPPROTO_IPIP)
		goto out;

	if (unlikely(!xpath_ipip_decap(skb)))
	{
		printk(KERN_INFO "XPath: cannot remove IP header\n");
		goto out;
	}

	/* if we perform TLB load balancing, we need to update states in RX path */
	if (xpath_load_balancing != TLB)
		goto out;

	/* after decap outer IP header, we need to get the inner IP header */
	iph = ip_hdr(skb);

	/* we only handle TCP ACK packets */
	if (iph->protocol != IPPROTO_TCP || !(tcph = tcp_hdr(skb)) || !(tcph->ack))
		goto out;

	/* Note that in reverse direction, local = destion, remote = source */
	xpath_set_flow_4tuple(&f, iph->daddr, iph->saddr, ntohs(tcph->dest), ntohs(tcph->source));
	flow_ptr = xpath_search_flow_table(&ft, &f);
	if (unlikely(!flow_ptr))
		goto out;

	/* initialize ACK Seq */
	if (unlikely(flow_ptr->info.ack_seq == 0))
		flow_ptr->info.ack_seq = ntohl(tcph->ack_seq);

	/* start a ECN measurement cycle */
	if (flow_ptr->info.ecn_start_time.tv64 == 0)
		flow_ptr->info.ecn_start_time = ktime_get();

	if (unlikely(!seq_after(ntohl(tcph->ack_seq), flow_ptr->info.ack_seq)))
		goto out;

	/* get ACK data in bytes */
	bytes_acked = ntohl(tcph->ack_seq) - flow_ptr->info.ack_seq;
	flow_ptr->info.ack_seq = ntohl(tcph->ack_seq);

	spin_lock_irqsave(&(flow_ptr->lock), tmp);
	flow_ptr->info.bytes_acked_total += bytes_acked;
	if (tcph->ece)
		flow_ptr->info.bytes_acked_ecn += bytes_acked;
	spin_unlock_irqrestore(&(flow_ptr->lock), tmp);

	//if (xpath_enable_debug)
	//	printk(KERN_INFO "Bytes ACKed %u\n", bytes_acked);
out:
        return NF_ACCEPT;
}

/* Install Netfilter hooks. Return true if it succeeds */
bool xpath_netfilter_init(void)
{
        /* register outgoing Netfilter hook */
        xpath_nf_hook_out.hook = xpath_hook_func_out;
        xpath_nf_hook_out.hooknum = NF_INET_POST_ROUTING;
        xpath_nf_hook_out.pf = PF_INET;
        xpath_nf_hook_out.priority = NF_IP_PRI_FIRST;

        if (unlikely(nf_register_hook(&xpath_nf_hook_out)))
        {
                printk(KERN_INFO "XPath: cannot register TX Netfilter hook\n");
                return false;
        }

        /* register incoming Netfilter hook */
        xpath_nf_hook_in.hook = xpath_hook_func_in;
        xpath_nf_hook_in.hooknum = NF_INET_PRE_ROUTING;
        xpath_nf_hook_in.pf = PF_INET;
        xpath_nf_hook_in.priority = NF_IP_PRI_FIRST;

        if (unlikely(nf_register_hook(&xpath_nf_hook_in)))
        {
                printk(KERN_INFO "XPath: cannot register RX Netfilter hook\n");
                return false;
        }

        return true;
}

/* Uninstall Netfilter hooks */
void xpath_netfilter_exit(void)
{
        nf_unregister_hook(&xpath_nf_hook_out);
        nf_unregister_hook(&xpath_nf_hook_in);
}
