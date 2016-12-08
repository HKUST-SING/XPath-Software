#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/atomic.h>

#include "flow_table.h"
#include "params.h"

/* Print a flow information. Operation: "Add", "Delete", etc.*/
void xpath_print_flow_entry(struct xpath_flow_entry *f, char *operation)
{
	char local_ip[16] = {0};   //Local IP address
	char remote_ip[16] = {0};  //Remote IP address

	if (unlikely(!f)) {
		printk(KERN_INFO "xpath_print_flow_entry: NULL pointer\n");
		return;
	}

	snprintf(local_ip, 16, "%pI4", &(f->local_ip));
	snprintf(remote_ip, 16, "%pI4", &(f->remote_ip));

	if (operation)
		printk(KERN_INFO "XPath: %s a flow (%s:%hu to %s:%hu)\n",
				 operation,
				 local_ip,
				 f->local_port,
				 remote_ip,
				 f->remote_port);
	else
		printk(KERN_INFO "XPath: flow (%s:%hu to %s:%hu)\n",
				 local_ip,
				 f->local_port,
				 remote_ip,
				 f->remote_port);
}

/* Print a Flow List */
void xpath_print_flow_list(struct xpath_flow_list *fl)
{
	struct xpath_flow_entry *ptr = NULL;

	if (unlikely(!fl)) {
		printk(KERN_INFO "xpath_print_flow_list: NULL pointer\n");
		return;
	}

	list_for_each_entry(ptr, &(fl->head_node), list)
		xpath_print_flow_entry(ptr, NULL);
}

/* Print a Flow Table */
void xpath_print_flow_table(struct xpath_flow_table *ft)
{
	int i = 0;

	if (unlikely(!ft)) {
		printk(KERN_INFO "xpath_print_flow_table: NULL pointer\n");
		return;
	}

	printk(KERN_INFO "XPath: current flow table\n");

	for (i = 0; i < XPATH_FLOW_HASH_RANGE; i++) {
		if (ft->flow_lists[i].len == 0)
			continue;

        	printk(KERN_INFO "XPath: flowlist %d has %u flows\n",
				 i,
				 ft->flow_lists[i].len);
		xpath_print_flow_list(&(ft->flow_lists[i]));
	}

	printk(KERN_INFO "XPath: %d flows in total\n", atomic_read(&(ft->size)));
}

/* Hash function, calculate the flow should be inserted into which xpath_flow_list */
inline unsigned int xpath_hash_flow(struct xpath_flow_entry *f)
{
	if (likely(f))
		return (((f->local_ip >> 24) + 1) * \
			((f->remote_ip >> 24) + 1) * \
			(f->local_port + 1) * \
			(f->remote_port + 1)) % XPATH_FLOW_HASH_RANGE;
	else {
		printk(KERN_INFO "xpath_hash_flow: NULL pointer\n");
		return 0;
	}
}

/* Determine whether two flows are identical */
inline bool xpath_equal_flow(struct xpath_flow_entry *f1,
			     struct xpath_flow_entry *f2)
{
	if (likely(f1 && f2))
		return (f1->local_ip == f2->local_ip) && \
		       (f1->remote_ip == f2->remote_ip) && \
		       (f1->local_port == f2->local_port) && \
		       (f1->remote_port == f2->remote_port);
	else {
		printk(KERN_INFO "xpath_equal_flow: NULL pointer\n");
		return false;
	}
}

/* Initialize the info of a Flow */
bool xpath_init_flow_info(struct xpath_flow_info *info)
{
	if (likely(info)) {
		info->path_id = 0;
		info->last_tx_time = ktime_set(0, 0);
		info->ack_seq = 0;
		info->bytes_sent = 0;
		return true;
	} else {
		printk(KERN_INFO "xpath_init_flow_info: NULL pointer\n");
		return false;
	}
}

/* Initialize a Flow */
bool xpath_init_flow_entry(struct xpath_flow_entry *f)
{
	if (likely(f)) {
		f->local_ip = 0;
		f->remote_ip = 0;
		f->local_port = 0;
		f->remote_port = 0;
		INIT_LIST_HEAD(&(f->list));
		spin_lock_init(&(f->lock));
		xpath_init_flow_info(&(f->info));
		return true;
	} else {
		printk(KERN_INFO "xpath_init_flow_entry: NULL pointer\n");
		return false;
	}
}

/* Initialize a Flow List */
bool xpath_init_flow_list(struct xpath_flow_list *fl)
{
	if (likely(fl)) {
		fl->len = 0;
		INIT_LIST_HEAD(&(fl->head_node));
		spin_lock_init(&(fl->lock));
		return true;
	} else {
		printk(KERN_INFO "xpath_init_flow_list: NULL pointer\n");
		return false;
	}
}

/* Initialize a Flow Table */
bool xpath_init_flow_table(struct xpath_flow_table *ft)
{
	int i = 0;
	struct xpath_flow_list *buf = NULL;

	if (unlikely(!ft)) {
		printk(KERN_INFO "xpath_init_flow_table: NULL pointer\n");
		return false;
	}

	buf = vmalloc(XPATH_FLOW_HASH_RANGE * sizeof(struct xpath_flow_list));
	if (buf) {
		ft->flow_lists = buf;
		atomic_set(&(ft->size), 0);

		for (i = 0; i < XPATH_FLOW_HASH_RANGE; i++) {
			if (!xpath_init_flow_list(&(ft->flow_lists[i])))
				return false;
		}

		return true;
	} else {
		printk(KERN_INFO "xpath_init_flow_table: vmalloc error\n");
		return false;
	}
}

/* set 4 tuples (src/dst IP and src/dst port) of the flow entry */
void xpath_set_flow_4tuple(struct xpath_flow_entry *f,
			   u32 local_ip,
			   u32 remote_ip,
			   u16 local_port,
			   u16 remote_port)
{
	if (unlikely(!f))
		return;

	f->local_ip = local_ip;
	f->remote_ip = remote_ip;
	f->local_port = local_port;
	f->remote_port = remote_port;
}

/* Search and return the pointer of given flow in a Flow List */
struct xpath_flow_entry *xpath_search_flow_list(struct xpath_flow_list *fl,
						struct xpath_flow_entry *f)
{
	struct xpath_flow_entry *ptr = NULL;

	if (unlikely(!fl || !f)) {
		printk(KERN_INFO "xpath_search_flow_list: NULL pointer\n");
		return NULL;
	}

	list_for_each_entry(ptr, &(fl->head_node), list)
	{
		if (xpath_equal_flow(ptr, f))
			return ptr;
	}

	return NULL;
}

/* Search the information for a given Flow in a Flow Table */
struct xpath_flow_entry *xpath_search_flow_table(struct xpath_flow_table *ft,
						 struct xpath_flow_entry *f)
{
	unsigned int index = 0;

	if (unlikely(!ft || !f)) {
		printk(KERN_INFO "xpath_search_flow_table: NULL pointer\n");
		return NULL;
	}

	index = xpath_hash_flow(f);
	return xpath_search_flow_list(&(ft->flow_lists[index]), f);
}

/* Insert a Flow into a Flow List and return true if it succeeds */
bool xpath_insert_flow_list(struct xpath_flow_list *fl,
			    struct xpath_flow_entry *f,
			    int flags)
{
	struct xpath_flow_entry *buf = NULL;
	unsigned long tmp;	//variable for save current states of irq

	if (unlikely(!fl || !f)) {
		printk(KERN_INFO "xpath_insert_flow_list: NULL pointer\n");
		return false;
	}

	/* The flow entry exists in this Flow List */
	if (xpath_search_flow_list(fl, f)) {
		printk(KERN_INFO "xpath_insert_flow_list: equal flow\n");
		return false;
	} else {
		buf = kmalloc(sizeof(struct xpath_flow_entry), flags);
		if (!buf) {
			printk(KERN_INFO "xpath_insert_flow_list: kmalloc error\n");
			return false;
		}

		*buf = *f;
		INIT_LIST_HEAD(&(buf->list));

		spin_lock_irqsave(&(fl->lock), tmp);
		list_add_tail(&(buf->list), &(fl->head_node));
		fl->len++;
		spin_unlock_irqrestore(&(fl->lock), tmp);

		return true;
	}
}

/* Insert a Flow into a Flow Table and return true if it succeeds */
bool xpath_insert_flow_table(struct xpath_flow_table *ft,
			     struct xpath_flow_entry *f,
			     int flags)
{
	unsigned int index = 0;

	if (unlikely(!ft || !f)) {
		printk(KERN_INFO "xpath_insert_flow_table: NULL pointer\n");
		return false;
	}

	index = xpath_hash_flow(f);
	if (xpath_insert_flow_list(&(ft->flow_lists[index]), f, flags)) {
		atomic_inc(&(ft->size));
		return true;
	} else {
		return false;
	}
}

/* Delete a Flow from a Flow List and return true if the delete succeeds */
bool xpath_delete_flow_list(struct xpath_flow_list *fl,
			    struct xpath_flow_entry *f)
{
	struct xpath_flow_entry *ptr, *next;
	unsigned long tmp;

	if (unlikely(!fl || !f)) {
		printk(KERN_INFO "xpath_delete_flow_list: NULL pointer\n");
		return false;
	}

	list_for_each_entry_safe(ptr, next, &(fl->head_node), list) {
		if (xpath_equal_flow(ptr, f)) {
			spin_lock_irqsave(&(fl->lock), tmp);
			list_del(&(ptr->list));
			kfree(ptr);
			fl->len--;
			spin_unlock_irqrestore(&(fl->lock), tmp);
			return true;
		}
	}

	return false;
}

/* Delete a Flow from a Flow Table and return true if the delete succeeds */
bool xpath_delete_flow_table(struct xpath_flow_table *ft,
			     struct xpath_flow_entry *f)
{
	bool result = false;
	unsigned int index = 0;

	if (unlikely(!ft || !f)) {
		printk(KERN_INFO "xpath_delete_flow_table: NULL pointer\n");
		return 0;
	}

	index = xpath_hash_flow(f);
	result = xpath_delete_flow_list(&(ft->flow_lists[index]), f);

	if (result)
		atomic_dec(&(ft->size));

	return result;
}

/* Delete all flow entries in this Flow List */
bool xpath_clear_flow_list(struct xpath_flow_list *fl)
{
	struct xpath_flow_entry *ptr, *next;
	unsigned long tmp;

	if (unlikely(!fl)) {
		printk(KERN_INFO "xpath_clear_flow_list: NULL pointer\n");
		return false;
	}

	if (fl->len > 0) {
		spin_lock_irqsave(&(fl->lock), tmp);
		list_for_each_entry_safe(ptr, next, &(fl->head_node), list) {
			list_del(&(ptr->list));
			kfree(ptr);
			fl->len--;
		}
		spin_unlock_irqrestore(&(fl->lock), tmp);
	}

	return true;
}

/* Delete all flow entries in this Flow Table */
bool xpath_clear_flow_table(struct xpath_flow_table *ft)
{
	int i = 0;

	if (unlikely(!ft)) {
		printk(KERN_INFO "xpath_clear_table: NULL pointer\n");
		return false;
	}

	for (i = 0; i < XPATH_FLOW_HASH_RANGE; i++) {
		if (unlikely(!xpath_clear_flow_list(&(ft->flow_lists[i]))))
			printk(KERN_INFO "Cannot clear flow list %d\n", i);
	}

	atomic_set(&(ft->size), 0);
	return true;
}

bool xpath_exit_flow_table(struct xpath_flow_table *ft)
{
	if (likely(xpath_clear_flow_table(ft))) {
		vfree(ft->flow_lists);
		return true;
	} else {
		return false;
	}
}
