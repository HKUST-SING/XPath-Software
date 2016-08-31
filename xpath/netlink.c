#include <linux/ctype.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include "path_table.h"
#include "netlink_msg.h"

#define MAX_ARGS_NUM 100

static struct sock *nl_sk = NULL;
/* Path Table */
extern struct xpath_path_table pt;

static bool get_args_from_msg(char *msg,
                              unsigned int *args,
                              unsigned int *num_args);
static bool handle_insert_msg(char *msg);
static void on_receiving_data(struct sk_buff *skb);

static bool get_args_from_msg(char *msg,
                              unsigned int *args,
                              unsigned int *num_args)
{
        char *ptr;
        unsigned int arg_val;
        unsigned int digit;

        *num_args = 0;
        arg_val = 0;
        for (ptr = msg; ptr && *ptr; ptr++)
        {
                if (*ptr == SEP)
                {
                        if (*num_args > MAX_ARGS_NUM)
                                return false;

                        args[(*num_args)++] = arg_val;
                        arg_val = 0;
                }
                else
                {
                        if (likely(isdigit(*ptr)))
                        {
                                digit = *ptr - '0';
                                arg_val = arg_val * 10 + digit;
                        }
                        else
                        {
                                return false;
                        }
                }
        }

        return true;
}

static bool handle_insert_msg(char *msg)
{
        unsigned int daddr;
        unsigned int num_paths;
        unsigned int *paths;
        unsigned int num_args;
        unsigned int args[MAX_ARGS_NUM];

        if (unlikely(!get_args_from_msg(msg, args, &num_args) || (num_args < 3)))
        {
                printk(KERN_INFO "XPath: receive invalid insert msg: %s\n", msg);
                return false;
        }

        num_paths = args[0];
        daddr = args[1];
        paths = &args[2];
        //printk(KERN_INFO "num_paths: %u daddr: %u\n", num_paths, daddr);
        return xpath_insert_path_table(&pt, daddr, num_paths, paths);
}

/* When receive a Netlink message */
static void on_receiving_data(struct sk_buff *skb)
{
        struct nlmsghdr *nlh;

        if (unlikely(!skb))
        {
                printk(KERN_INFO "on_receiving_data: NULL pointer\n");
                return;
        }

        nlh = (struct nlmsghdr *)skb->data;
        switch (nlh->nlmsg_type)
        {
                case OP_INSERT:
                        if (unlikely(!handle_insert_msg(NLMSG_DATA(nlh))))
                                printk(KERN_INFO "XPath: insert path fails\n");
                        return;

                case OP_PRINT:
                        if (unlikely(!xpath_print_path_table(&pt)))
                                printk(KERN_INFO "XPath: print path table fails\n");
                        return;

                case OP_CLEAR:
                        if (unlikely(!xpath_clear_path_table(&pt)))
                                printk(KERN_INFO "XPath: clear path table fails\n");
                        else
                                printk(KERN_INFO "XPath: clear path table\n");
                        return;

                default:
                        printk(KERN_INFO "XPath: unknown msg type: %u\n",
                                         nlh->nlmsg_type);
        }
}

/* Install Netlink socket */
bool xpath_netlink_init(void)
{
        struct netlink_kernel_cfg cfg =
        {
                .groups = 0,
                .input = on_receiving_data,
        };

        nl_sk = netlink_kernel_create(&init_net, NETLINK_XPATH, &cfg);

        if (likely(nl_sk))
                return true;
        else
                return false;
}

/* Uninstall Netlink socket */
void xpath_netlink_exit(void)
{
        if (likely(nl_sk && nl_sk->sk_socket))
                sock_release(nl_sk->sk_socket);
}
