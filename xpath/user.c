#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include "netlink_msg.h"

#define STR_LEN 11 /* max 32-bit unsigned int is 4,294,967,296 (11 chars to store the string)*/

struct sockaddr_nl src_addr, dst_addr;
struct iovec iov;
int sockfd;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;

void print_usage(char *program)
{
        if (!program) {
                return;
        }

        printf("Usage: %s [option]\n", program);
        printf("%s [dest] [path ID 1] [path IP 1] .. insert a new path entry to path table\n", OP_STR_INSERT);
        printf("%s                                   print path table\n", OP_STR_PRINT);
        printf("%s                                   clear all path entries in the table\n", OP_STR_CLEAR);
        printf("%s                                   display help information\n", OP_STR_HELP);
}

int main(int argc, char **argv)
{
        unsigned int i;
        unsigned int num_paths;
        unsigned int daddr;
        char str[STR_LEN] = {0};
        char formatted_msg[MAX_MSG_LEN] = {0};  //Netlink message
        unsigned int ip;        //path IP
        int id; //path ID

        if ((sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_XPATH)) < 0) {
                printf("Cannot create socket\n");
                return 0;
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

        //insert message: [program] [OP_STR_INSERT] [dst] [path ID 1] [path IP 1] ....
        if (argc >= 5 && (argc - 3) % 2 == 0 && strcmp(argv[1], OP_STR_INSERT) == 0 ) {
                // msg format : num_paths, dest IP, path ID 1, path IP 1, ..
                num_paths = (argc - 3) / 2;
                sprintf(formatted_msg, "%u%c", num_paths, SEP);

                for (i = 2; i < argc; i++) {
                        memset(str, 0, STR_LEN);
                        //A IP address: destination or path IP
                        if (i % 2 == 0) {
                                if (inet_pton(AF_INET, argv[i], &ip) == 0) {
                                        printf("[ERROR] Invalid IP address: %s\n", argv[i]);
                                        return 0;
                                } else {
                                        sprintf(str, "%u", ip);
                                }
                        //A path ID (integer)
                        } else {
                                id = atoi(argv[i]);
                                if (id < 0) {
                                        printf("[ERROR] Invalid path ID: %s\n", argv[i]);
                                } else {
                                        sprintf(str, "%d", id);
                                }
                        }

                        if (strlen(formatted_msg) + strlen(str) + 2 > MAX_MSG_LEN) {
                                printf("[ERROR] Too many paths\n");
                                return 0;
                        }

                        strcat(formatted_msg, str);
                        strcat(formatted_msg, SEP_STR);
                }

                strcpy(NLMSG_DATA(nlh), formatted_msg);
                nlh->nlmsg_type = OP_INSERT;
                //printf("%s\n", formatted_msg);

        //print message: [program] [OP_STR_PRINT]
        } else if (argc == 2 && strcmp(argv[1], OP_STR_PRINT) == 0) {
                nlh->nlmsg_type = OP_PRINT;

        //clear message: [program] [OP_STR_CLEAR]
        } else if (argc == 2 && strcmp(argv[1], OP_STR_CLEAR) == 0) {
                nlh->nlmsg_type = OP_CLEAR;
        } else {
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
