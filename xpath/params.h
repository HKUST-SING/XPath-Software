#ifndef PARAMS_H
#define PARAMS_H

/* ECN sample intervalin microsecond */
#define XPATH_ECN_SAMPLE_US 800
/* ECN sample minimum bytes */
#define XPATH_ECN_SAMPLE_BYTES 10240

/* Hash range for XPath flow table (Number of flow lists) */
#define XPATH_FLOW_HASH_RANGE 256
/* Hash range for XPath path table */
#define XPATH_PATH_HASH_RANGE 256

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

/* what load balancing machanism does XPath performs */
extern int xpath_load_balancing;
/* whether print necessary debug information */
extern int xpath_enable_debug;
/* flowcell threshold in bytes */
extern int xpath_flowcell_thresh;

struct xpath_param
{
        char name[64];
        int *ptr;
};

extern struct xpath_param xpath_params[3];

/* Intialize parameters and register sysctl. Return true if it succeeds. */
bool xpath_params_init(void);
/* Unregister sysctl */
void xpath_params_exit(void);

#endif
