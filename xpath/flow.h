#ifndef __FLOW_H__
#define __FLOW_H__

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/list.h>

/* Hash range (Number of flow lists) */
#define XPath_HASH_RANGE 256

struct XPath_Flow_Info
{
    atomic_t path_id;   //current path ID
    atomic_t byte_count;    //Presto
};

/* A TCP flow is defined by 4-tuple <local_ip, remote_ip, local_port, remote_port> and its related information */
struct XPath_Flow
{
    u32 local_ip;   //Local IP address
    u32 remote_ip;  //Remote IP address
    u16 local_port; //Local port
    u16 remote_port;    //Remote port
    struct XPath_Flow_Info info; //Information for this flow
    struct list_head list;	//linked list
};

/* Link List of Flows */
struct XPath_Flow_List
{
    struct list_head head_node;    //head node of the flow list
    unsigned int len;   //total number of flows in the list
    spinlock_t lock;    //lock for this flow list
};

/* Hash Table of Flows */
struct XPath_Flow_Table
{
    struct XPath_Flow_List* flow_lists;  //array of linked lists to store per-flow information
    atomic_t size;
};

/* Print functions */
void XPath_Print_Flow(struct XPath_Flow* f, char* operation);
void XPath_Print_List(struct XPath_Flow_List* fl);
void XPath_Print_Table(struct XPath_Flow_Table* ft);

inline unsigned int XPath_Hash_Flow(struct XPath_Flow* f);
inline bool XPath_Equal_Flow(struct XPath_Flow* f1, struct XPath_Flow* f2);

/* Initialization functions */
bool XPath_Init_Info(struct XPath_Flow_Info* info);
bool XPath_Init_Flow(struct XPath_Flow* f);
bool XPath_Init_List(struct XPath_Flow_List* fl);
bool XPath_Init_Table(struct XPath_Flow_Table* ft);

/* Search functions: search a flow entry from flow table/list */
struct XPath_Flow* XPath_Search_List(struct XPath_Flow_List* fl, struct XPath_Flow* f);
struct XPath_Flow* XPath_Search_Table(struct XPath_Flow_Table* ft, struct XPath_Flow* f);

/* Insert functions: insert a new flow entry to flow table/list */
bool XPath_Insert_List(struct XPath_Flow_List* fl, struct XPath_Flow* f, int flags);
bool XPath_Insert_Table(struct XPath_Flow_Table* ft,struct XPath_Flow* f, int flags);

/* Delete functions: delete a flow entry from flow table/list */
bool XPath_Delete_List(struct XPath_Flow_List* fl, struct XPath_Flow* f);
bool XPath_Delete_Table(struct XPath_Flow_Table* ft, struct XPath_Flow* f);

/* Clear functions: clear flow entries from flow table/list */
bool XPath_Clear_List(struct XPath_Flow_List* fl);
bool XPath_Clear_Table(struct XPath_Flow_Table* ft);

/* Exit functions: delete whole flow table */
bool XPath_Exit_Table(struct XPath_Flow_Table* ft);

#endif
