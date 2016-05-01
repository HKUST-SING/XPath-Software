#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/atomic.h>

#include "path_table.h"


/* Calculate hash code for destination address */
static unsigned int xpath_daddr_hash_code(unsigned int daddr);

/* print information of a XPath entry */
void xpath_print_path_entry(struct xpath_path_entry *entry);

/* Initialize XPath path table */
bool xpath_init_path_table(struct xpath_path_table* pt)
{
    struct hlist_head *buf = NULL;
    int i = 0;

	if (unlikely(!pt))
	{
		printk(KERN_INFO "xpath_init_path_table: NULL pointer\n");
		return false;
	}

    buf = vmalloc(XPATH_PATH_HASH_RANGE * sizeof(struct hlist_head));
    if (likely(buf))
    {
        pt->lists = buf;
        for (i = 0; i < XPATH_PATH_HASH_RANGE; i++)
            INIT_HLIST_HEAD(&pt->lists[i]);

        return true;
    }
    else
    {
        printk(KERN_INFO "xpath_init_path_table: vmalloc error\n");
        return false;
    }
}

/* Search available paths to 'daddr' */
struct xpath_path_entry *xpath_search_path_table(struct xpath_path_table *pt, unsigned int daddr)
{
    unsigned int index = 0;
    struct xpath_path_entry *entry = NULL;
    struct hlist_node *ptr = NULL;

    if (unlikely(!pt))
        return NULL;

    index = xpath_daddr_hash_code(daddr);

    hlist_for_each_entry_safe(entry, ptr, &pt->lists[index], hlist)
    {
        if (entry->daddr == daddr)
            return entry;
    }

    return NULL;
}

/* Insert a new path entry (daadr, num_paths, paths) to XPath path table */
bool xpath_insert_path_table(struct xpath_path_table *pt, unsigned int daddr, unsigned int num_paths, unsigned int *paths)
{
    unsigned int index = 0;
    struct xpath_path_entry *entry = NULL;
    struct hlist_node *ptr = NULL;
    unsigned int *new_paths = NULL;
    atomic_t *new_congestions = NULL;
    unsigned int *old_paths = NULL;
    atomic_t *old_congestions = NULL;

    unsigned int i = 0;


    if (unlikely(!pt || !paths || (num_paths == 0)))
        return false;

    index = xpath_daddr_hash_code(daddr);
    hlist_for_each_entry_safe(entry, ptr, &pt->lists[index], hlist)
    {
        /* if the entry already exists, we just update it */
        if (entry->daddr == daddr)
        {
            new_paths = vmalloc(sizeof(unsigned int) * num_paths);
            new_congestions = vmalloc(sizeof(atomic_t) * num_paths);

            if (unlikely(!new_paths || !new_congestions))
            {
                vfree(new_paths);
                vfree(new_congestions);
                return false;
            }
            else
            {
                /* copy paths tonew_paths */
                memcpy(new_paths, paths, sizeof(unsigned int) * num_paths);

                /* initialize congestion degress to 0 for all paths */
                for (i = 0; i < num_paths; i++)
                    atomic_set(&new_congestions[i], 0);

                /* update information for this entry */
                old_paths = entry->paths;
                old_congestions = entry->congestions;
                entry->paths = new_paths;
                entry->congestions = new_congestions;
                entry->num_paths = num_paths;
                vfree(old_paths);
                vfree(old_congestions);

                return true;
            }
        }
    }

    /* insert a new entry */
    entry = vmalloc(sizeof(struct xpath_path_entry));
    new_paths = vmalloc(sizeof(unsigned int) * num_paths);
    new_congestions = vmalloc(sizeof(atomic_t) * num_paths);

    if (unlikely(!entry || !new_paths || !new_congestions))
    {
        vfree(entry);
        vfree(new_paths);
        vfree(new_congestions);
        return false;
    }
    else
    {
        /* copy paths tonew_paths */
        memcpy(new_paths, paths, sizeof(unsigned int) * num_paths);

        /* initialize congestion degress to 0 for all paths */
        for (i = 0; i < num_paths; i++)
            atomic_set(&new_congestions[i], 0);

        INIT_HLIST_NODE(&entry->hlist);
        entry->daddr = daddr;
        entry->paths = new_paths;
        entry->congestions = new_congestions;
        entry->num_paths = num_paths;
        hlist_add_head(&entry->hlist, &pt->lists[index]);

        return true;
    }
}

/* Clear all path entries in XPath path table */
bool xpath_clear_path_table(struct xpath_path_table *pt)
{
    unsigned int i;
    struct xpath_path_entry *entry;
    struct hlist_node *ptr;

    if (unlikely(!pt))
        return false;

    for (i = 0; i < XPATH_PATH_HASH_RANGE; i++)
    {
        hlist_for_each_entry_safe(entry, ptr, &pt->lists[i], hlist)
        {
            hlist_del(&entry->hlist);
            vfree(entry->paths);
            vfree(entry->congestions);
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

    for (i = 0; i < XPATH_PATH_HASH_RANGE; i++)
    {
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
    printk(KERN_INFO "  Dest %s (%u paths): \n", ip, entry->num_paths);

    for (i = 0; i < entry->num_paths; i++)
    {
        snprintf(ip, 16, "%pI4", &(entry->paths[i]));
        printk(KERN_INFO "      %s (%d) \n", ip, atomic_read(&(entry->congestions[i])));
    }
}

/* Calculate hash code for destination address */
static unsigned int xpath_daddr_hash_code(unsigned int daddr)
{
    unsigned int sum = 0;
    int i = 0;

    for (i = 0; i < 4; i++)
    {
        sum = sum * 10 + daddr / (1 << (8 * (3 - i)));
        daddr %= 1 << (8 * (3 - i));
    }

    return sum % XPATH_PATH_HASH_RANGE;
}
