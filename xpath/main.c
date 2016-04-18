#include <linux/module.h>
#include <linux/kernel.h>

#include "netfilter.h"
#include "flow.h"

/* param_dev: NIC to operate XPath */
char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate XPath (NULL=all)");
module_param(param_dev, charp, 0);

int param_port __read_mostly = 0;
MODULE_PARM_DESC(param_port, "TCP port to match (0=all)");
module_param(param_port, int, 0);

/* Flow Table */
struct XPath_Flow_Table ft;

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

    /* Initialize flow table */
    XPath_Init_Table(&ft);

    if (likely(XPath_Netfilter_Init()))
    {
        printk(KERN_INFO "XPath: start on %s (TCP port %d)\n", param_dev? param_dev:"any interface", param_port);
        return 0;
    }
    else
        return -1;
}

static void xpath_module_exit(void)
{
	XPath_Netfilter_Exit();
    XPath_Exit_Table(&ft);

    printk(KERN_INFO "XPath: stop working\n");
}

module_init(xpath_module_init);
module_exit(xpath_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Linux kernel module for XPath (load balancing)");
