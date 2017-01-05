#include <linux/sysctl.h>
#include <linux/string.h>

#include "params.h"

int xpath_load_balancing = ECMP;
int xpath_enable_debug = 0;
int xpath_flowcell_thresh = 65536;	//64KB
int xpath_flowlet_thresh = 500;	//500us
int xpath_ack_prio = 1;	//enable ACK prioritization by default

int xpath_tlb_ecn_low_thresh = 102;	//10%
int xpath_tlb_ecn_high_thresh = 512;	//50%
int xpath_tlb_rtt_low_thresh = 200;	//200us
int xpath_tlb_rtt_high_thresh = 800;	//800us
int xpath_tlb_reroute_bytes_thresh = 102400;	//100KB
int xpath_tlb_reroute_time_thresh = 100;	//100us
int xpath_tlb_reroute_rate_thresh = 450;	//450Mbps
int xpath_tlb_reroute_prob = 50;	//50%
int xpath_tlb_ecn_sample_us = 800;	//800us
int xpath_tlb_ecn_sample_bytes = 15360;	//15KB

int xpath_params_min[NUM_PARAMS] =
{
	ECMP,	//load balancing
	0,	//enable debug
	0,	//flowcell threshold in byte
	0,	//flowlet threshold in microsecond
	0,	//enable ACK prioritization
	0,	//ECN fraction low threshold
	0,	//ECN fraction high threshold
	0,	//RTT low threshold in microsecond
	0,	//RTT high threshold in microsecond
	0,	//reroute bytes sent threshold
	0,	//reroute time interval threshold in microsecond
	0,	//reroute rate threshold in mbps
	0,	//reroute probability (%)
	0,	//ECN sample interval in microsecond
	0	//ECN sample bytes
};

int xpath_params_max[NUM_PARAMS] =
{
	TLB,	//load balancing
	1,	//enable debug
	104857600,	//flowcell threshold in byte (max: 100MB)
	5000,	//flowlet threshold in microsecond (max: 5ms)
	1,	//enable ACK prioritization
	1024,	//ECN fraction low threshold
	1024,	//ECN fraction high threshold
	5000,	//RTT low threshold in microsecond (max: 5ms)
	5000,	//RTT high threshold in microsecond (max: 5ms)
	104857600,	//reroute bytes sent threshold (max: 100MB)
	5000,	//reroute time interval threshold in microsecond (max: 5ms)
	10000,	//reroute rate threshold in mbps (max: 10Gbps)
	100,	//reroute probability (max: 100%)
	5000,	//ECN sample interval in microsecond (max: 5ms)
	104857600	//ECN sample bytes (max: 100MB)
};

struct xpath_param xpath_params[NUM_PARAMS] =
{
	{"load_balancing", &xpath_load_balancing},
	{"enable_debug", &xpath_enable_debug},
	{"flowcell_thresh", &xpath_flowcell_thresh},
	{"flowlet_thresh", &xpath_flowlet_thresh},
	{"ack_prio", &xpath_ack_prio},
	{"tlb_ecn_low_thresh", &xpath_tlb_ecn_low_thresh},
	{"tlb_ecn_high_thresh", &xpath_tlb_ecn_high_thresh},
	{"tlb_rtt_low_thresh", &xpath_tlb_rtt_low_thresh},
	{"tlb_rtt_high_thresh", &xpath_tlb_rtt_high_thresh},
	{"tlb_reroute_bytes_thresh", &xpath_tlb_reroute_bytes_thresh},
	{"tlb_reroute_time_thresh", &xpath_tlb_reroute_time_thresh},
	{"tlb_reroute_rate_thresh", &xpath_tlb_reroute_rate_thresh},
	{"tlb_reroute_prob", &xpath_tlb_reroute_prob},
	{"tlb_ecn_sample_us", &xpath_tlb_ecn_sample_us},
	{"tlb_ecn_sample_bytes", &xpath_tlb_ecn_sample_bytes},
};

struct ctl_table xpath_params_table[NUM_PARAMS];

struct ctl_path xapath_params_path[] =
{
	{ .procname = "xpath" },
	{ },
};

struct ctl_table_header *xpath_sysctl = NULL;

bool xpath_params_init(void)
{
	int i;
	struct ctl_table *entry = NULL;
	memset(xpath_params_table, 0, sizeof(xpath_params_table));

	for (i = 0; i < NUM_PARAMS; i ++) {
		entry = &xpath_params_table[i];
		entry->procname = xpath_params[i].name;
		entry->data = xpath_params[i].ptr;
		entry->mode = 0644;
		entry->proc_handler = &proc_dointvec_minmax;
		entry->extra1 = &xpath_params_min[i];
		entry->extra2 = &xpath_params_max[i];
		entry->maxlen = sizeof(int);
	}

	xpath_sysctl = register_sysctl_paths(xapath_params_path, xpath_params_table);

	if (likely(xpath_sysctl))
		return true;
	else
		return false;
}

void xpath_params_exit(void)
{
	if (likely(xpath_sysctl))
        	unregister_sysctl_table(xpath_sysctl);
}
