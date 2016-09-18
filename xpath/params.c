#include <linux/sysctl.h>
#include <linux/string.h>

#include "params.h"

int xpath_load_balancing = ECMP;
int xpath_enable_debug = 0;
int xpath_flowcell_thresh = 65536;

int xpath_params_min[3] = {ECMP, 0, 0};
int xpath_params_max[3] = {TLB, 1, 104857600};

struct xpath_param xpath_params[3] =
{
	{"load_balancing", &xpath_load_balancing},
	{"enable_debug", &xpath_enable_debug},
	{"flowcell_thresh", &xpath_flowcell_thresh},
};

struct ctl_table xpath_params_table[3];

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

	for (i = 0; i < 3; i ++)
	{
		entry = &xpath_params_table[i];
		entry->procname = xpath_params[i].name;
		entry->data = xpath_params[i].ptr;
		entry->mode = 0644;
		entry->proc_handler = &proc_dointvec_minmax;
		entry->extra1 = &xpath_params_min[i];
		entry->extra2 = &xpath_params_max[i];
		entry->maxlen = sizeof(int);
	}

	xpath_sysctl = register_sysctl_paths(xapath_params_path,
					     xpath_params_table);

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
