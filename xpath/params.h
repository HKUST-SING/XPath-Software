#ifndef PARAMS_H
#define PARAMS_H

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

/* what load balancing machanism does XPath performs */
extern int xpath_load_balancing;
/* whether print necessary debug information */
extern int xpath_enable_debug;

struct xpath_param
{
    char name[64];
    int *ptr;
};

extern struct xpath_param xpath_params[2];

/* Intialize parameters and register sysctl. Return true if it succeeds. */
bool xpath_params_init(void);
/* Unregister sysctl */
void xpath_params_exit(void);

#endif
