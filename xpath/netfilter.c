#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>

#include "netfilter.h"
#include "flow_table.h"
#include "path_table.h"
#include "net_util.h"
#include "params.h"

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

/* Hook function for outgoing packets */
static unsigned int xpath_hook_func_out(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    struct iphdr tiph;  /* tunnel (outer) IP header */
    struct tcphdr *tcph;
    u16 payload_len = 0;    /* TCP payload length */
    struct xpath_flow_entry f;
    struct xpath_flow_entry *flow_ptr = NULL;
    struct xpath_path_entry *path_ptr = NULL;
    u32 path_ip = 0;    /* IP address of the path */
    int path_id = 0;    /* Default path index */
    unsigned short hash_key = 0;

    if (likely(out) && param_dev && strncmp(out->name, param_dev, IFNAMSIZ) != 0)
        return NF_ACCEPT;

    /* we only filter TCP packets */
    if (likely(iph) && iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);
        if (param_port != 0 && ntohs(tcph->source) != param_port && ntohs(tcph->dest) != param_port)
            return NF_ACCEPT;

        xpath_init_flow_entry(&f);
        f.local_ip = iph->saddr;
        f.remote_ip = iph->daddr;
        f.local_port = (u16)ntohs(tcph->source);
        f.remote_port = (u16)ntohs(tcph->dest);

        path_ptr = xpath_search_path_table(&pt, iph->daddr);
        /* cannot find path information */
        if (unlikely(!path_ptr || path_ptr->num_paths == 0))
        {
            if (xpath_enable_debug)
                printk(KERN_INFO "XPath: cannot find path information\n");

            return NF_DROP;
        }
        if (tcph->syn)
        {
            /* modify MSS for TCP SYN packets */
            if (unlikely(!xpath_reduce_tcp_mss(skb, sizeof(struct iphdr))))
            {
                if (xpath_enable_debug)
                    printk(KERN_INFO "XPath: cannot modify TCP MSS\n");
                return NF_DROP;
            }

            /* insert a new flow entry to the flow table */
            if (unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC)))
            {
                if (xpath_enable_debug)
                    printk(KERN_INFO "XPath: insert flow fails\n");
            }
            /*else
                printk(KERN_INFO "XPath: insert succeeds\n");*/
        }
        else if (tcph->fin || tcph->rst)
        {
            if (!xpath_delete_flow_table(&ft, &f))
            {
                if (xpath_enable_debug)
                    printk(KERN_INFO "XPath: delete flow fails\n");
            }
            /*else
                printk(KERN_INFO "XPath: delete succeeds\n");*/
        }
        else
        {
            flow_ptr = xpath_search_flow_table(&ft, &f);
            if (flow_ptr)
            {
                /* flow-level ECMP load balancing */
                if (xpath_load_balancing == ECMP)
                {
                    hash_key = xpath_flow_hash_crc16(f.local_ip, f.local_port, f.remote_ip, f.remote_port);
                    /* hash_key_space = 1 << 16; path_id = hash_key * path_ptr->num_paths / region_size; */
                    path_id = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
                }
                /* packet-level random packet spraying (RPS) load balancing */
                else if (xpath_load_balancing == RPS)
                {
                    path_id = flow_ptr->info.path_id;
                    /* path_id = (path_id + 1) % path_ptr->num_paths */
                    path_id = (++path_id >= path_ptr->num_paths)? path_id - path_ptr->num_paths : path_id;
                    flow_ptr->info.path_id = path_id;
                }
                /* flowcell-level Presto load balancing */
                else if (xpath_load_balancing == PRESTO)
                {
                    path_id = flow_ptr->info.path_id;
                    payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
                    if (flow_ptr->info.byte_count + (int)payload_len > 65535)
                    {
                        flow_ptr->info.byte_count = payload_len;
                        /* path_id = (path_id + 1) % path_ptr->num_paths */
                        path_id = (++path_id >= path_ptr->num_paths)? path_id - path_ptr->num_paths : path_id;
                        flow_ptr->info.path_id = path_id;
                    }
                    else
                    {
                        flow_ptr->info.byte_count += payload_len;
                    }
                }
                else
                {
                    if (xpath_enable_debug)
                        printk(KERN_INFO "XPath: unknown load balancing scheme %d\n", xpath_load_balancing);
                    /* do not add outer IP header to such packet */
                    return NF_ACCEPT;
                }
            }
        }

        path_ip = path_ptr->paths[path_id];

        /* construct tunnel (outer) IP header */
        tiph.version = 4;
        tiph.ihl = sizeof(struct iphdr) >> 2;
        tiph.tot_len =  htons(ntohs(iph->tot_len) + sizeof(struct iphdr));
        tiph.id = iph->id;
        tiph.frag_off = iph->frag_off;
        tiph.protocol = IPPROTO_IPIP;
        tiph.tos = iph->tos;
        tiph.daddr = path_ip;
        tiph.saddr = iph->saddr;
        tiph.ttl = iph->ttl;
        tiph.check = 0;
        tiph.check = ip_fast_csum(&tiph, tiph.ihl);

        /* add tunnel (outer) IP header */
        if (unlikely(!xpath_ipip_encap(skb, &tiph, out)))
        {
            if (xpath_enable_debug)
                printk(KERN_INFO "XPath: cannot add outer IP header\n");

            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

/* Hook function for incoming packets */
static unsigned int xpath_hook_func_in(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);

    if (likely(in) && param_dev && strncmp(in->name, param_dev, IFNAMSIZ) != 0)
        return NF_ACCEPT;

    if (likely(iph) && iph->protocol == IPPROTO_IPIP)
    {
        if (unlikely(!xpath_ipip_decap(skb)))
            printk(KERN_INFO "XPath: cannot remove outer IP header\n");
    }

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
        printk(KERN_INFO "XPath: cannot register Netfilter hook at NF_INET_POST_ROUTING\n");
        return false;
    }

    /* register incoming Netfilter hook */
    xpath_nf_hook_in.hook = xpath_hook_func_in;
    xpath_nf_hook_in.hooknum = NF_INET_PRE_ROUTING;
    xpath_nf_hook_in.pf = PF_INET;
    xpath_nf_hook_in.priority = NF_IP_PRI_FIRST;

    if (unlikely(nf_register_hook(&xpath_nf_hook_in)))
    {
        printk(KERN_INFO "XPath: cannot register Netfilter hook at NF_INET_PRE_ROUTING\n");
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
