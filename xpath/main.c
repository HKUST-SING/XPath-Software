#include <linux/module.h>
#include <linux/kernel.h>

#include "netfilter.h"
#include "netlink.h"
#include "params.h"
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

/*
 * The following two functions are related to param_table_operation
 * To clear flow table: echo -n clear > /sys/module/xpath/parameters/param_table_operation
 * To print flow table: echo -n print > /sys/module/xpath/parameters/param_table_operation
 */
static int xpath_set_operation(const char *val, struct kernel_param *kp);
static int xpath_noget(const char *val, struct kernel_param *kp);
module_param_call(param_table_operation,
                  xpath_set_operation,
                  xpath_noget,
                  NULL,
                  S_IWUSR); //Write permission by owner

static int xpath_set_operation(const char *val, struct kernel_param *kp)
{
        //Clear flow table
        if (strncmp(val, "clear", 5) == 0)
        {
                printk(KERN_INFO "XPath: clear flow table\n");
                xpath_clear_flow_table(&ft);
        }
        //Print flow table
        else if (strncmp(val, "print", 5) == 0)
        {
                printk(KERN_INFO "XPath: print flow table\n");
                xpath_print_flow_table(&ft);
        }
        else
        {
                printk(KERN_INFO "XPath: unknown flow table operation %s\n", val);
        }

        return 0;
}

static int xpath_noget(const char *val, struct kernel_param *kp)
{
        return 0;
}

static int xpath_module_init(void)
{
        int i = 0;

        /* get interface */
        if (param_dev)
        {
                /* trim */
                for (i = 0; i < 32 && param_dev[i] != '\0'; i++)
                {
                        if (param_dev[i] == '\n')
                        {
                                param_dev[i] = '\0';
                                break;
                        }
                }
        }

        if (likely(xpath_params_init() &&
                   xpath_init_flow_table(&ft) &&
                   xpath_init_path_table(&pt) &&
                   xpath_netfilter_init() &&
                   xpath_netlink_init()))
        {
                printk(KERN_INFO "XPath: start on %s (TCP port %d)\n",
                                 param_dev? param_dev:"any interface",
                                 param_port);
                return 0;
        }
        else
        {
                printk(KERN_INFO "XPath: cannot start\n");
                return -1;
        }
}

static void xpath_module_exit(void)
{
        xpath_netfilter_exit();
        xpath_netlink_exit();

        xpath_exit_path_table(&pt);
        xpath_exit_flow_table(&ft);
        xpath_params_exit();

        printk(KERN_INFO "XPath: stop working\n");
}

module_init(xpath_module_init);
module_exit(xpath_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Linux kernel module for XPath (load balancing)");
