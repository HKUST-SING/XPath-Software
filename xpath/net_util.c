#include "net_util.h"

#include <linux/tcp.h>
#include <net/ip_tunnels.h>
#include "params.h"

static const int CRC_HASH_TABLE[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

/* add ECT and modify DSCP for IP header */
void xpath_modify_ip_header(struct iphdr *iph, u32 payload_len)
{
	if (unlikely(!iph))
		return;

	/* high priority for pure ACK packets */
	if (xpath_ack_prio == 1 && payload_len == 0)
		iph->tos = HIGH_PRIO_DSCP << 2;

	/* ECN capable (to avoid switch bug) */
	if (!INET_ECN_is_capable(iph->tos))
		iph->tos |= INET_ECN_ECT_0;

	/* calculate IP header checksum */
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);
}

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

        while (1) {
                /* TCP option kind: MSS (2) */
                if (*ptr == 2) {
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

        if (likely(result)) {
                tcph->check = 0;
                tcph->check = csum_tcpudp_magic(iph->saddr,
                                                iph->daddr,
                                                tcp_len,
                                                iph->protocol,
                                                csum_partial((char *)tcph,
                                                tcp_len, 0));
                skb->ip_summed = CHECKSUM_UNNECESSARY;
        }

        return result;
}

/**
 *  IPIP encapsulation
 *  @skb: target socket buffer structure
 *  @tiph: tunnel IP header (outer IP header)
 *  @out: output network device
 *  Return true if it succeeds
 */
bool xpath_ipip_encap(struct sk_buff *skb,
                      struct iphdr *tiph,
                      const struct net_device *out)
{
        struct iphdr *iph = ip_hdr(skb);
        unsigned int headroom = sizeof(struct iphdr) + LL_RESERVED_SPACE(out);

        /* if we don't have enough headroom */
        if (skb_headroom(skb) < headroom) {
                if (unlikely(skb_cow_head(skb, headroom - skb_headroom(skb)))) {
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
        if (likely(iph && iph->protocol == IPPROTO_IPIP)) {
                out_tos = iph->tos;
                skb_pull(skb, iph->ihl<<2);
                skb_reset_network_header(skb);
                skb->transport_header = skb->network_header + (iph->ihl<<2);

                /* Get the inner IP header */
                iph = ip_hdr(skb);
                /* We should update ToS of the inner IP header */
                if (out_tos != iph->tos) {
                        iph->tos = out_tos;
                        /* Update the checksum of the inner IP header */
                        iph->check = 0;
                        iph->check = ip_fast_csum(iph, iph->ihl);
                }

                return true;
        } else {
                return false;
        }
}

/* Compute flow hash key by crc16 */
unsigned short xpath_flow_hash_crc16(unsigned int local_ip,
                                     unsigned int remote_ip,
                                     unsigned short local_port,
                                     unsigned short remote_port)
{
        unsigned short shorts[] = {local_ip & 0xff, local_ip >> 16, local_port,
                                   remote_ip & 0xff, remote_ip >> 16, remote_port};
        unsigned char *byte_ptr = (unsigned char *)shorts;
        unsigned int num_bytes = 12;
        unsigned short crc = 0;

        while (num_bytes--) {
                crc = (crc << 8) ^ CRC_HASH_TABLE[(crc >> 8) ^ (*byte_ptr)];
                byte_ptr++;
        }

        return crc;
}
