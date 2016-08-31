#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include "netlink_msg.h"

#define IP_STR_LEN 11 /* 11 should be enough since the maximum IP integet is 2^32 = 4,294,967,296 */

struct sockaddr_nl src_addr, dst_addr;
struct iovec iov;
int sockfd;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;


void print_usage(char *program)
{
        if (!program)
        {
                return;
        }

        printf("Usage: %s [option]\n", program);
        printf("-i [dest] [path1] [path2] .. insert a new path entry to XPath path table\n");
        printf("-p                           print XPath path table\n");
        printf("-c                           clear all path entries in the table\n");
        printf("-h                           display help information\n");
}

int main(int argc, char **argv)
{
        unsigned int i;
        unsigned int num_paths;
        unsigned int daddr;
        char ip_str[IP_STR_LEN] = {0};
        unsigned int ip;


        char formatted_msg[MAX_MSG_LEN] = {0};
        sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_XPATH);
        if (sockfd < 0)
        {
                printf("Cannot create socket\n");
                return -1;
        }

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();
        src_addr.nl_groups = 0;
        bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr));

        memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.nl_family = AF_NETLINK;
        dst_addr.nl_pid = 0;
        dst_addr.nl_groups = 0;

        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_MSG_LEN));

        nlh->nlmsg_len = NLMSG_SPACE(MAX_MSG_LEN);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_type = 0;

        if ((argc >= 4) && (strcmp(argv[1], OP_STR_INSERT) == 0))
        {
                // msg format : num_paths, dest IP, path id 0, path id 1, ..
                num_paths = argc - 3;
                sprintf(formatted_msg, "%u%c", num_paths, SEP);
                for (i = 2; i < argc; i++)
                {
                        if (inet_pton(AF_INET, argv[i], &ip) == 0)
                        {
                                printf("[ERROR] Invalid IP address: %s\n", argv[i]);
                                return 0;
                        }

                        memset(ip_str, 0, IP_STR_LEN);
                        sprintf(ip_str, "%u", ip);
                        if (strlen(formatted_msg) + strlen(ip_str) + 2 > MAX_MSG_LEN)
                        {
                                printf("[ERROR] Too many paths\n");
                                return 0;
                        }

                        strcat(formatted_msg, ip_str);
                        strcat(formatted_msg, SEP_STR);
                }

                strcpy(NLMSG_DATA(nlh), formatted_msg);
                nlh->nlmsg_type = OP_INSERT;
        }
        else if ((argc == 2) && (strcmp(argv[1], OP_STR_PRINT) == 0))
        {
                nlh->nlmsg_type = OP_PRINT;
        }
        else if ((argc == 2) && (strcmp(argv[1], OP_STR_CLEAR) == 0))
        {
                nlh->nlmsg_type = OP_CLEAR;
        }
        else
        {
                printf("[ERROR] Invalid options\n");
                print_usage(argv[0]);
                return 0;
        }

        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dst_addr;
        msg.msg_namelen = sizeof(dst_addr);

        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        sendmsg(sockfd, &msg, 0);
        close(sockfd);

        return 0;
}
