#include <linux/sysctl.h>
#include <linux/string.h>

#include "params.h"

int xpath_load_balancing = ECMP;
int xpath_load_balancing_min = ECMP;
int xpath_load_balancing_max = RPS;

int xpath_enable_debug = 0;
int xpath_enable_debug_min = 0;
int xpath_enable_debug_max = 1;

struct xpath_param xpath_params[2] =
{
	{"load_balancing", &xpath_load_balancing},
	{"enable_debug", &xpath_enable_debug},
};

struct ctl_table xpath_params_table[2];

struct ctl_path xapath_params_path[] =
{
	{ .procname = "xpath" },
	{ },
};

struct ctl_table_header *xpath_sysctl = NULL;

bool xpath_params_init(void)
{
    struct ctl_table *entry = NULL;
    memset(xpath_params_table, 0, sizeof(xpath_params_table));

    /* xpath.load_balancing */
    entry = &xpath_params_table[0];
    entry->procname = xpath_params[0].name;
    entry->data = xpath_params[0].ptr;
    entry->mode = 0644;
	entry->proc_handler = &proc_dointvec_minmax;
	entry->extra1 = &xpath_load_balancing_min;
    entry->extra2 = &xpath_load_balancing_max;
    entry->maxlen=sizeof(int);

    /* xpath.enable_debug */
    entry = &xpath_params_table[1];
    entry->procname = xpath_params[1].name;
    entry->data = xpath_params[1].ptr;
    entry->mode = 0644;
    entry->proc_handler = &proc_dointvec_minmax;
    entry->extra1 = &xpath_enable_debug_min;
    entry->extra2 = &xpath_enable_debug_max;
    entry->maxlen=sizeof(int);

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
