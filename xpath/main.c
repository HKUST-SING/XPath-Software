#include <linux/module.h>
#include <linux/kernel.h>

#include "netfilter.h"
#include "netlink.h"
#include "flow_table.h"
#include "path_table.h"

/* param_dev: NIC to operate XPath */
char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate XPath (NULL=all)");
module_param(param_dev, charp, 0);

int param_port __read_mostly = 5001;
MODULE_PARM_DESC(param_port, "TCP port to match (0=all)");
module_param(param_port, int, 0);

/* Flow Table */
struct xpath_flow_table ft;
/* Path Table */
struct xpath_path_table pt;

static int xpath_module_init(void)
{
    int i = 0;

    /* get interface */
    if (param_dev)
    {
        /* trim */
        for (i = 0; i < 32 && param_dev[i] != '\0'; i++)
        {
            if(param_dev[i] == '\n')
            {
                param_dev[i] = '\0';
                break;
            }
        }
    }

    /* Initialize flow table and path table */
    xpath_init_flow_table(&ft);
    xpath_init_path_table(&pt);

    if (likely(xpath_netfilter_init() && xpath_netlink_init()))
    {
        printk(KERN_INFO "XPath: start on %s (TCP port %d)\n", param_dev? param_dev:"any interface", param_port);
        return 0;
    }
    else
        return -1;
}

static void xpath_module_exit(void)
{
	xpath_netfilter_exit();
    xpath_netlink_exit();

    xpath_exit_path_table(&pt);
    xpath_exit_flow_table(&ft);

    printk(KERN_INFO "XPath: stop working\n");
}

module_init(xpath_module_init);
module_exit(xpath_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Linux kernel module for XPath (load balancing)");
