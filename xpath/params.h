#ifndef PARAMS_H
#define PARAMS_H

/* Hash range for XPath flow table (Number of flow lists) */
#define XPATH_FLOW_HASH_RANGE 256
/* Hash range for XPath path table */
#define XPATH_PATH_HASH_RANGE 256

#define XPATH_PATH_GROUP_SIZE 16

#define HIGH_PRIO_DSCP 1

/* flow-level ECMP load balancing */
#define ECMP 0
/* flowcell-level Presto load balancing */
#define PRESTO 1
/* packet-level random packet spraying (RPS) load balancing */
#define RPS 2
/* FlowBender load balancing */
#define FLOWBENDER 3
/* Our solution: TLB */
#define TLB 4

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

/* Intialize parameters and register sysctl. Return true if it succeeds. */
bool xpath_params_init(void);
/* Unregister sysctl */
void xpath_params_exit(void);

#endif
