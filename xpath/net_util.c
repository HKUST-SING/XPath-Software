#include "net_util.h"

#include <linux/tcp.h>
#include <net/ip_tunnels.h>

/**
 *  Modify TCP MSS option in SYN packets.
 *  @reduce_size: size to reduce for maximum sergment
 *  Return true if it succeeds
 */
bool xpath_reduce_tcp_mss(struct sk_buff *skb, unsigned short int reduce_size)
{
    struct iphdr *iph = ip_hdr(skb);    //IP header
    struct tcphdr *tcph = tcp_hdr(skb); //TCP header
    unsigned int tcp_len = skb->len - (iph->ihl<<2);    //TCP packet length
    unsigned int tcph_len = (unsigned int)(tcph->doff<<2);  //TCP header length
    unsigned char *ptr = (unsigned char*)tcph + sizeof(struct tcphdr);
    unsigned short int mss; //Maximum segment size (MSS)
    unsigned int offset;    //length of the TCP option
    bool result = false;

    if (unlikely(!tcph->syn))
        return result;

	/* if we can not modify this packet */
	if (unlikely(skb_linearize(skb) != 0))
		return result;

	while (1)
	{
		/* TCP option kind: MSS (2) */
		if (*ptr == 2)
		{
			mss = ntohs(*((unsigned short int*)(ptr + 2)));
			mss = mss - reduce_size;
			*(unsigned short int*)(ptr + 2) = htons(mss);
            result = true;
			break;
		}

		/* TCP option kind: No-Operation (1) */
		if (*ptr == 1)
			offset = 1;
		/* other TCP options */
		else
			/* get length of this TCP option */
			offset = (unsigned int)*(ptr + 1);

		if (ptr - (unsigned char *)tcph + offset >= tcph_len)
			break;
		else
			ptr += offset;
	}

    if (likely(result))
	{
        tcph->check = 0;
        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, iph->protocol, csum_partial((char *)tcph, tcp_len, 0));
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    }

    return result;
}

/**
 *  IPIP encapsulation
 *  @tiph: tunnel IP header (outer IP header)
 *  @out: output network device
 *  Return true if it succeeds
 */
bool xpath_ipip_encap(struct sk_buff *skb, struct iphdr *tiph, const struct net_device *out)
{
    struct iphdr *iph = ip_hdr(skb);
    unsigned int max_headroom = sizeof(struct iphdr) + LL_RESERVED_SPACE(out);  /* The extra header space needed */

    /* if we don't have enough headroom */
    if (skb_headroom(skb) < max_headroom)
    {
        if (unlikely(skb_cow_head(skb, max_headroom - skb_headroom(skb))))
        {
            printk(KERN_INFO "Unable to expand sk_buff\n");
            return false;
        }
    }

    skb = iptunnel_handle_offloads(skb, false, SKB_GSO_IPIP);
    /* push down and install the outer IP header */
    skb_push(skb, sizeof(struct iphdr));
    skb_reset_network_header(skb);

    /* construct the outer IP header */
    iph = (struct iphdr *)skb_network_header(skb);
    *iph = *tiph;

    return true;
}

/* IPIP decapsulation. Return true if it succeeds */
bool xpath_ipip_decap(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    u8 out_tos;

    /* We only decap IPIP packets */
    if (likely(iph && iph->protocol == IPPROTO_IPIP))
    {
        out_tos = iph->tos;
        skb_pull(skb, iph->ihl<<2);
        skb_reset_network_header(skb);
        skb->transport_header = skb->network_header + (iph->ihl<<2);

        /* Get the inner IP header */
        iph = ip_hdr(skb);
        /* We should update ToS of the inner IP header when
           the outer IP header has a different ToS (get ECN marked ). */
        if (out_tos != iph->tos)
        {
            iph->tos = out_tos;
            /* Update the checksum of the inner IP header */
            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);
        }

        return true;
    }
    else
    {
        return false;
    }
}
