#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/atomic.h>

#include "flow.h"

/* Print a flow information. Operation: "Add", "Delete", etc.*/
void XPath_Print_Flow(struct XPath_Flow* f, char* operation)
{
	char local_ip[16] = {0};   //Local IP address
	char remote_ip[16] = {0};  //Remote IP address

	if (unlikely(!f))
	{
		printk(KERN_INFO "XPath_Print_Flow: NULL pointer\n");
		return;
	}

	snprintf(local_ip, 16, "%pI4", &(f->local_ip));
	snprintf(remote_ip, 16, "%pI4", &(f->remote_ip));

	if (operation)
		printk(KERN_INFO "XPath: %s a flow record from %s:%hu to %s:%hu\n", operation, local_ip, f->local_port, remote_ip, f->remote_port);
	else
		printk(KERN_INFO "XPath: a flow record from %s:%hu to %s:%hu\n", local_ip, f->local_port, remote_ip, f->remote_port);
}

/* Print a Flow List */
void XPath_Print_List(struct XPath_Flow_List* fl)
{
	struct XPath_Flow* ptr = NULL;

	if (unlikely(!fl))
	{
		printk(KERN_INFO "XPath_Print_List: NULL pointer\n");
		return;
	}

	list_for_each_entry(ptr, &(fl->head_node), list)
		XPath_Print_Flow(ptr, NULL);
}

/* Print a Flow Table */
void XPath_Print_Table(struct XPath_Flow_Table* ft)
{
	int i = 0;

	if (unlikely(!ft))
	{
		printk(KERN_INFO "XPath_Print_Table: NULL pointer\n");
		return;
	}

	printk(KERN_INFO "XPath: current flow table\n");
	for (i = 0; i < XPath_HASH_RANGE; i++)
	{
		if (ft->flow_lists[i].len > 0)
		{
        	printk(KERN_INFO "XPath: flowlist %d has %u flows\n", i, ft->flow_lists[i].len);
			XPath_Print_List(&(ft->flow_lists[i]));
		}
	}
	printk(KERN_INFO "XPath: there are %d flows in total\n", atomic_read(&(ft->size)));
}

/* Hash function, calculate the flow should be inserted into which XPath_Flow_List */
inline unsigned int XPath_Hash_Flow(struct XPath_Flow* f)
{
	//return a value in [0,HASH_RANGE-1]
	if (likely(f))
		return (((f->local_ip >> 24) + 1) * ((f->remote_ip >> 24) + 1) * (f->local_port + 1) * (f->remote_port + 1)) % XPath_HASH_RANGE;
	else
	{
		printk(KERN_INFO "XPath_Hash_Flow: NULL pointer\n");
		return 0;
	}
}

/* Determine whether two Flows are equal. <local_ip, remote_ip, local_port, remote_port> determines a flow */
inline bool XPath_Equal_Flow(struct XPath_Flow* f1, struct XPath_Flow* f2)
{
	if (likely(f1 && f2))
		return (f1->local_ip == f2->local_ip) && (f1->remote_ip == f2->remote_ip) && (f1->local_port == f2->local_port) && (f1->remote_port == f2->remote_port);
	else
	{
		printk(KERN_INFO "XPath_Equal_Flow: NULL pointer\n");
		return false;
	}
}

/* Initialize the info of a Flow */
bool XPath_Init_Info(struct XPath_Flow_Info* info)
{
	if (likely(info))
	{
		atomic_set(&(info->path_id), 0);
		atomic_set(&(info->byte_count), 0);
		return true;
	}
	else
	{
		printk(KERN_INFO "XPath_Init_Info: NULL pointer\n");
		return false;
	}
}

/* Initialize a Flow */
bool XPath_Init_Flow(struct XPath_Flow* f)
{
	if (likely(f))
	{
		f->local_ip = 0;
		f->remote_ip = 0;
		f->local_port = 0;
		f->remote_port = 0;
		INIT_LIST_HEAD(&(f->list));
    	//Initialize the Info for this Flow
		XPath_Init_Info(&(f->info));
		return true;
	}
	else
    {
		printk(KERN_INFO "XPath_Init_Flow: NULL pointer\n");
		return false;
	}
}

/* Initialize a Flow List */
bool XPath_Init_List(struct XPath_Flow_List* fl)
{
	if (likely(fl))
	{
		fl->len = 0;
		INIT_LIST_HEAD(&(fl->head_node));
		spin_lock_init(&(fl->lock));
		return true;
	}
	else
	{
		printk(KERN_INFO "XPath_Init_List: NULL pointer\n");
		return false;
	}
}

/* Initialize a Flow Table */
bool XPath_Init_Table(struct XPath_Flow_Table* ft)
{
	int i = 0;
	struct XPath_Flow_List* buf = NULL;

	if (unlikely(!ft))
	{
		printk(KERN_INFO "XPath_Init_Table: NULL pointer\n");
		return false;
	}

	buf = vmalloc(XPath_HASH_RANGE * sizeof(struct XPath_Flow_List));
	if (buf)
	{
		ft->flow_lists = buf;
		atomic_set(&(ft->size), 0);

		for (i = 0; i < XPath_HASH_RANGE; i++)
		{
			if (!XPath_Init_List(&(ft->flow_lists[i])))
				return false;
		}

		return true;
	}
	else
	{
		printk(KERN_INFO "XPath_Init_Table: vmalloc error\n");
		return false;
	}
}

/* Search and return the pointer of given flow in a Flow List */
struct XPath_Flow* XPath_Search_List(struct XPath_Flow_List* fl, struct XPath_Flow* f)
{
	struct XPath_Flow* ptr = NULL;

	if (unlikely(!fl || !f))
	{
		printk(KERN_INFO "XPath_Search_List: NULL pointer\n");
		return NULL;
	}

	list_for_each_entry(ptr, &(fl->head_node), list)
	{
		if (XPath_Equal_Flow(ptr, f))
			return ptr;
	}

	return NULL;
}

/* Search the information for a given Flow in a Flow Table */
struct XPath_Flow* XPath_Search_Table(struct XPath_Flow_Table* ft, struct XPath_Flow* f)
{
	unsigned int index = 0;

	if (unlikely(!ft || !f))
	{
		printk(KERN_INFO "XPath_Search_Table: NULL pointer\n");
		return NULL;
	}

	index = XPath_Hash_Flow(f);
	return XPath_Search_List(&(ft->flow_lists[index]), f);
}

/* Insert a Flow into a Flow List and return true if it succeeds */
bool XPath_Insert_List(struct XPath_Flow_List* fl, struct XPath_Flow* f, int flags)
{
	struct XPath_Flow* buf = NULL;
	unsigned long tmp;	//variable for save current states of irq

	if (unlikely(!fl || !f))
	{
		printk(KERN_INFO "XPath_Insert_List: NULL pointer\n");
		return false;
	}

	//No such flow entry in this Flow List
	if (XPath_Search_List(fl, f))
	{
    	printk(KERN_INFO "XPath_Insert_List: equal flow\n");
    	return false;
	}
	else
	{
		//Allocate memory
		buf = kmalloc(sizeof(struct XPath_Flow), flags);
		if (!buf)
		{
			printk(KERN_INFO "XPath_Insert_List: kmalloc error\n");
			return false;
		}
		*buf = *f;
		INIT_LIST_HEAD(&(buf->list));
		//spin_lock_init(&(buf->lock));

		spin_lock_irqsave(&(fl->lock), tmp);
		list_add_tail(&(buf->list), &(fl->head_node));
		fl->len++;
		spin_unlock_irqrestore(&(fl->lock), tmp);

		return true;
	}
}

/* Insert a Flow into a Flow Table and return true if it succeeds */
bool XPath_Insert_Table(struct XPath_Flow_Table* ft, struct XPath_Flow* f, int flags)
{
	unsigned int index = 0;

	if (unlikely(!ft || !f))
	{
		printk(KERN_INFO "XPath_Insert_Table: NULL pointer\n");
		return false;
	}

	index = XPath_Hash_Flow(f);
	if (XPath_Insert_List(&(ft->flow_lists[index]), f, flags))
	{
		atomic_inc(&(ft->size));
		return true;
	}
	else
		return false;
}

/* Delete a Flow from a Flow List and return true if the delete succeeds */
bool XPath_Delete_List(struct XPath_Flow_List* fl, struct XPath_Flow* f)
{
	struct XPath_Flow *ptr, *next;
	unsigned long tmp;

	if (unlikely(!fl || !f))
	{
		printk(KERN_INFO "XPath_Delete_List: NULL pointer\n");
		return false;
	}

	list_for_each_entry_safe(ptr, next, &(fl->head_node), list)
	{
		if (XPath_Equal_Flow(ptr, f))
		{
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
bool XPath_Delete_Table(struct XPath_Flow_Table* ft, struct XPath_Flow* f)
{
	bool result = false;
	unsigned int index = 0;

	if (unlikely(!ft || !f))
	{
		printk(KERN_INFO "XPath_Delete_Table: NULL pointer\n");
		return 0;
	}

	index = XPath_Hash_Flow(f);
	result = XPath_Delete_List(&(ft->flow_lists[index]), f);
	if (result)
		atomic_dec(&(ft->size));

	return result;
}

/* Delete all flow entries in this Flow List */
bool XPath_Clear_List(struct XPath_Flow_List* fl)
{
	struct XPath_Flow *ptr, *next;
	unsigned long tmp;

	if (unlikely(!fl))
	{
		printk(KERN_INFO "XPath_Clear_List: NULL pointer\n");
		return false;
	}

	if (fl->len > 0)
	{
		spin_lock_irqsave(&(fl->lock), tmp);
		list_for_each_entry_safe(ptr, next, &(fl->head_node), list)
		{
			list_del(&(ptr->list));
			kfree(ptr);
			fl->len--;
		}
		spin_unlock_irqrestore(&(fl->lock), tmp);
	}

	return true;
}

/* Delete all flow entries in this Flow Table */
bool XPath_Clear_Table(struct XPath_Flow_Table* ft)
{
	int i = 0;

	if (unlikely(!ft))
	{
		printk(KERN_INFO "XPath_Clear_Table: NULL pointer\n");
		return false;
	}

	for (i = 0; i < XPath_HASH_RANGE; i++)
	{
		if (unlikely(!XPath_Clear_List(&(ft->flow_lists[i]))))
			printk(KERN_INFO "Cannot clear flow list %d\n", i);
	}

	atomic_set(&(ft->size), 0);
	return true;
}

bool XPath_Exit_Table(struct XPath_Flow_Table* ft)
{
	if (likely(XPath_Clear_Table(ft)))
	{
		vfree(ft->flow_lists);
		return true;
	}
	else
		return false;
}
