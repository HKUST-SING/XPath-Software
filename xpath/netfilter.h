#ifndef NETFILTER_H
#define NETFILTER_H

/* Install Netfilter hooks */
bool XPath_Netfilter_Init(void);

/* Uninstall Netfilter hooks */
void XPath_Netfilter_Exit(void);

#endif
