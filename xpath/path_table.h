#ifndef __PATH_TABLE_H__
#define __PATH_TABLE_H__

#include <linux/types.h>
#include <linux/list.h>

/* Some paths from the same source host to the same destination host */
struct xpath_path_entry
{
        unsigned int daddr;     /* destination host IP address (key of this struct) */
        unsigned int num_paths; /* number of paths in total */

        /* Each path has two attributes: IP address and group ID */
        unsigned int *path_ips; /* path IP addresses */
        unsigned int *path_group_ids;   /* path group IDs (map path to a path group */

        atomic_t current_path;  /* current path index, for per-packet loac balancing */
        struct hlist_node hlist;
};

/*
 * Currently, the path table is only a linked list.
 * Maybe we can extend it to a hash-table in the future.
 */
struct xpath_path_table
{
        struct hlist_head *lists;      
};

/* Initialize XPath path table */
bool xpath_init_path_table(struct xpath_path_table *pt);

/* Search available paths to 'daddr' */
struct xpath_path_entry *xpath_search_path_table(struct xpath_path_table *pt,
                                                 unsigned int daddr);

/* Insert a new path entry (daadr, num_paths, paths) to XPath path table */
bool xpath_insert_path_table(struct xpath_path_table *pt,
                             unsigned int daddr,
                             unsigned int num_paths,
                             unsigned int *paths);

/* Clear all path entries in XPath path table */
bool xpath_clear_path_table(struct xpath_path_table *pt);

/* Exit XPath path table. Release all resrouces. */
bool xpath_exit_path_table(struct xpath_path_table *pt);

/* print information of all entries in XPath path table */
bool xpath_print_path_table(struct xpath_path_table *pt);

#endif
