#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>

#include "netfilter.h"
#include "routing.h"
#include "flow_table.h"
#include "path_table.h"
#include "path_group.h"
#include "net_util.h"
#include "params.h"

/* borrow from codel_time_after in include/net/codel.h of Linux kernel */
#define seq_after(a, b) (typecheck(u32, a) && typecheck(u32, b) && ((s32)((a) - (b)) > 0))

/* Flow Table */
extern struct xpath_flow_table ft;
/* Path Table */
extern struct xpath_path_table pt;
/* Path Group */
extern struct xpath_group_entry pg[XPATH_PATH_GROUP_SIZE];

/* NIC device name */
extern char *param_dev;
/* TCP port */
extern int param_port;

/* Netfilter hook for outgoing packets */
static struct nf_hook_ops xpath_nf_hook_out;
/* Netfilter hook for incoming packets */
static struct nf_hook_ops xpath_nf_hook_in;

/* Hook function for outgoing packets */
static unsigned int xpath_hook_func_out(const struct nf_hook_ops *ops,
                                        struct sk_buff *skb,
                                        const struct net_device *in,
                                        const struct net_device *out,
                                        int (*okfn)(struct sk_buff *))
{
        struct iphdr *iph = ip_hdr(skb);
        struct iphdr tiph;	/* tunnel (outer) IP header */
        struct tcphdr *tcph;
        struct xpath_path_entry *path_ptr = NULL;
        u32 path_ip = 0;	/* IP address of the path */
	u32 payload_len = 0;	/* tcp payload length */

        if (likely(out) && param_dev && strncmp(out->name, param_dev, IFNAMSIZ) != 0)
                return NF_ACCEPT;

        /* we only filter TCP packets */
        if (likely(iph) && iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
                if (param_port != 0 &&
                    ntohs(tcph->source) != param_port &&
                    ntohs(tcph->dest) != param_port)
                        return NF_ACCEPT;

		payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
		path_ptr = xpath_search_path_table(&pt, iph->daddr);

                /* no available path */
                if (unlikely(!path_ptr || path_ptr->num_paths == 0)) {
			xpath_modify_ip_header(iph, payload_len);
			return NF_ACCEPT;
		}

                /* Reduce MSS value in SYN packets */
                if (tcph->syn &&
                    unlikely(!xpath_reduce_tcp_mss(skb, sizeof(struct iphdr)))) {
                        xpath_debug_info("XPath: cannot modify MSS\n");
                        return NF_DROP;
                }

                switch (xpath_load_balancing) {
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
                        case LETFLOW:
                                path_ip = letflow_routing(skb, path_ptr);
                                break;
                        case TLB:
                                path_ip = tlb_routing(skb, path_ptr);
                                break;
                        default:
			        printk(KERN_INFO "XPath: unknown LB scheme %d\n",
                                                 xpath_load_balancing);
		}

                /* find path IP, then construct tunnel (outer) IP header */
		if (likely(path_ip > 0)) {
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
			xpath_modify_ip_header(&tiph, payload_len);

		/* cannot find path IP */
                } else {
			xpath_modify_ip_header(iph, payload_len);
			return NF_ACCEPT;
		}

                /* add tunnel (outer) IP header */
		if (unlikely(!xpath_ipip_encap(skb, &tiph, out))) {
                        xpath_debug_info("XPath: cannot add IP header\n");
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

	if (unlikely(!xpath_ipip_decap(skb))) {
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

	if (unlikely(!seq_after(ntohl(tcph->ack_seq), flow_ptr->info.ack_seq)))
		goto out;

	/* get ACK data in bytes */
	bytes_acked = ntohl(tcph->ack_seq) - flow_ptr->info.ack_seq;

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

        if (unlikely(nf_register_hook(&xpath_nf_hook_out))) {
                printk(KERN_INFO "XPath: cannot register TX Netfilter hook\n");
                return false;
        }

        /* register incoming Netfilter hook */
        xpath_nf_hook_in.hook = xpath_hook_func_in;
        xpath_nf_hook_in.hooknum = NF_INET_PRE_ROUTING;
        xpath_nf_hook_in.pf = PF_INET;
        xpath_nf_hook_in.priority = NF_IP_PRI_FIRST;

        if (unlikely(nf_register_hook(&xpath_nf_hook_in))) {
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
