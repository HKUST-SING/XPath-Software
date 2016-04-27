#ifndef NETFILTER_H
#define NETFILTER_H

/* Install Netfilter hooks */
bool xpath_netfilter_init(void);

/* Uninstall Netfilter hooks */
void xpath_netfilter_exit(void);

#endif
