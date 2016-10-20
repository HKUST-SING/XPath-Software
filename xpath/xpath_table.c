#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/atomic.h>

#include "xpath_table.h"
#include "params.h"

/* Calculate hash code for destination address */
static unsigned int xpath_daddr_hash_code(unsigned int daddr);

/* print information of a XPath entry */
void xpath_print_path_entry(struct xpath_path_entry *entry);

/* Initialize XPath path table */
bool xpath_init_path_table(struct xpath_path_table* pt)
{
        struct hlist_head *buf = NULL;
        int i = 0;

        if (unlikely(!pt)) {
                printk(KERN_INFO "xpath_init_path_table: NULL pointer\n");
		return false;
	}

        buf = vmalloc(XPATH_PATH_HASH_RANGE * sizeof(struct hlist_head));
        if (likely(buf)) {
                pt->lists = buf;
                for (i = 0; i < XPATH_PATH_HASH_RANGE; i++)
                        INIT_HLIST_HEAD(&pt->lists[i]);

                return true;
        } else {
                printk(KERN_INFO "xpath_init_path_table: vmalloc error\n");
                return false;
        }
}

/* Search available paths to 'daddr' */
struct xpath_path_entry *xpath_search_path_table(struct xpath_path_table *pt,
                                                 unsigned int daddr)
{
        unsigned int index = 0;
        struct xpath_path_entry *entry = NULL;
        struct hlist_node *ptr = NULL;

        if (unlikely(!pt))
                return NULL;

        index = xpath_daddr_hash_code(daddr);

        hlist_for_each_entry_safe(entry, ptr, &pt->lists[index], hlist) {
                if (entry->daddr == daddr)
                        return entry;
        }

        return NULL;
}

/* Insert a new path entry (daadr, num_paths, paths) to XPath path table */
bool xpath_insert_path_table(struct xpath_path_table *pt,
                             unsigned int daddr,
                             unsigned int num_paths,
                             unsigned int *paths)
{
        unsigned int index, i;
        struct xpath_path_entry *entry = NULL;
        struct hlist_node *ptr = NULL;
        unsigned int *new_path_ips = NULL, *new_path_ids = NULL;

        if (unlikely(!pt || !paths || num_paths == 0))
                return false;

        index = xpath_daddr_hash_code(daddr);
        hlist_for_each_entry_safe(entry, ptr, &pt->lists[index], hlist) {
                /* if the entry already exists, return false */
                if (entry->daddr == daddr) {
                        printk(KERN_INFO "Path entry to %u exists\n", daddr);
                        return false;
                }
        }

        entry = vmalloc(sizeof(struct xpath_path_entry));
        new_path_ips = vmalloc(sizeof(unsigned int) * num_paths);
        new_path_ids = vmalloc(sizeof(unsigned int) * num_paths);

        if (unlikely(!entry || !new_path_ips || !new_path_ids)) {
                vfree(entry);
                vfree(new_path_ips);
                vfree(new_path_ids);
                return false;
        }

        //initialize
        for (i = 0; i < 2 * num_paths; i++) {
                if (i % 2 == 0) {       //path ID
                        new_path_ids[i / 2] = paths[i];
                } else {        //path IP
                        new_path_ips[i / 2] = paths[i];
                }
        }

        /* insert a new entry */
        INIT_HLIST_NODE(&entry->hlist);
        entry->daddr = daddr;
        entry->num_paths = num_paths;
        entry->path_ips = new_path_ips;
        entry->path_ids = new_path_ids;
        atomic_set(&entry->current_path, 0);
        hlist_add_head(&entry->hlist, &pt->lists[index]);
        return true;
}

/* Clear all path entries in XPath path table */
bool xpath_clear_path_table(struct xpath_path_table *pt)
{
        unsigned int i;
        struct xpath_path_entry *entry;
        struct hlist_node *ptr;

        if (unlikely(!pt))
                return false;

        for (i = 0; i < XPATH_PATH_HASH_RANGE; i++) {
            hlist_for_each_entry_safe(entry, ptr, &pt->lists[i], hlist) {
                    hlist_del(&entry->hlist);
                    vfree(entry->path_ips);
                    vfree(entry->path_ids);
                    vfree(entry);
            }
        }

        return true;
}

/* Exit XPath path table. Release all resrouces. */
bool xpath_exit_path_table(struct xpath_path_table *pt)
{
        if (unlikely(!pt))
                return false;

        xpath_clear_path_table(pt);
        vfree(pt->lists);
        return true;
}

/* print information of all entries in XPath path table */
bool xpath_print_path_table(struct xpath_path_table *pt)
{
        unsigned int i;
        struct xpath_path_entry *entry = NULL;
        struct hlist_node *ptr = NULL;

        if (unlikely(!pt))
                return false;

        for (i = 0; i < XPATH_PATH_HASH_RANGE; i++) {
                if (unlikely(!&pt->lists[i]) || hlist_empty(&pt->lists[i]))
                        continue;

                printk(KERN_INFO "Path List %u\n", i);
                hlist_for_each_entry_safe(entry, ptr, &pt->lists[i], hlist)
                        xpath_print_path_entry(entry);
        }

        return true;
}

/* print information of a XPath entry */
void xpath_print_path_entry(struct xpath_path_entry *entry)
{
        unsigned int i;
        char ip[16] = {0};

        if (unlikely(!entry || entry->num_paths == 0))
                return;

        snprintf(ip, 16, "%pI4", &(entry->daddr));
        printk(KERN_INFO " Dest %s (%u paths, current path: %u): \n",
                         ip,
                         entry->num_paths,
                         ((unsigned int)atomic_read(&entry->current_path)) % entry->num_paths);

        for (i = 0; i < entry->num_paths; i++) {
                snprintf(ip, 16, "%pI4", &(entry->path_ips[i]));
                printk(KERN_INFO "      %s (%d) \n", ip, entry->path_ids[i]);
        }
}

/* Calculate hash code for destination address */
static unsigned int xpath_daddr_hash_code(unsigned int daddr)
{
        unsigned int sum = 0;
        int i = 0;

        for (i = 0; i < 4; i++) {
                sum = sum * 10 + daddr / (1 << (8 * (3 - i)));
                daddr %= 1 << (8 * (3 - i));
        }

        return sum % XPATH_PATH_HASH_RANGE;
}
