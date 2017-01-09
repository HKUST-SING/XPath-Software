#ifndef PARAMS_H
#define PARAMS_H

/* Hash range for XPath flow table (Number of flow lists) */
#define XPATH_FLOW_HASH_RANGE 256
/* Hash range for XPath path table */
#define XPATH_PATH_HASH_RANGE 256
/* Number of path groups */
#define XPATH_PATH_GROUP_SIZE 16

/* DSCP value for high priority queue */
#define HIGH_PRIO_DSCP 1

/*
 * Length to Time (l2t) in nanosecond (ns)
 * Line Rate = 1 Gbit per second.
 * time_ns = len * 8 / 1G * 10^9 = = len * 8 = len << 3
 */
#define xpath_l2t_ns(pktlen) (pktlen << 3)

/* flow-level ECMP load balancing */
#define ECMP 0
/* flowcell-level Presto load balancing */
#define PRESTO 1
/* packet-level random packet spraying (RPS) load balancing */
#define RPS 2
/* FlowBender load balancing */
#define FLOWBENDER 3
/* LetFlow (NSDI'17) */
#define LETFLOW 4
/* Our solution: TLB */
#define TLB 5

#define NUM_PARAMS 15

/* what load balancing machanism does XPath performs */
extern int xpath_load_balancing;
/* whether print necessary debug information */
extern int xpath_enable_debug;
/* flowcell threshold in bytes */
extern int xpath_flowcell_thresh;
/* flowlet threshold in microsecond */
extern int xpath_flowlet_thresh;
/* whether enable reverse ACK prioritization */
extern int xpath_ack_prio;

/* TLB ECN low fraction threshold */
extern int xpath_tlb_ecn_low_thresh;
/* TLB ECN high fraction threshold */
extern int xpath_tlb_ecn_high_thresh;
/* TLB RTT low threshold in microsecond */
extern int xpath_tlb_rtt_low_thresh;
/* TLB RTT high threshold in microsecond */
extern int xpath_tlb_rtt_high_thresh;
/* TLB reroute bytes sent threshold */
extern int xpath_tlb_reroute_bytes_thresh;
/* TLB reroute time interval threshold in microsecond */
extern int xpath_tlb_reroute_time_thresh;
/* TLB reourte rate threshold in mbps */
extern int xpath_tlb_reroute_rate_thresh;
/* TLB reroute probability */
extern int xpath_tlb_reroute_prob;
/* TLB ECN sample interval in microsecond */
extern int xpath_tlb_ecn_sample_us;
/* TLB ECN minimum sample bytes */
extern int xpath_tlb_ecn_sample_bytes;


struct xpath_param
{
        char name[64];
        int *ptr;
};

extern struct xpath_param xpath_params[NUM_PARAMS];

/* Print debug information if necessary */
inline void xpath_debug_info(char *str);
/* Intialize parameters and register sysctl. Return true if it succeeds. */
bool xpath_params_init(void);
/* Unregister sysctl */
void xpath_params_exit(void);

#endif
