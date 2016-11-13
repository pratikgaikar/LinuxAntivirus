#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#include <linux/fs.h>
#include <linux/slab.h>
#include <stdbool.h>

//Linked list implementation of Queue
struct node{
        struct dentry *dir;
        struct node * next;
};


/*
 *function prototype
 */
void add_new_node(struct dentry *dir);
struct dentry *delete_node(void*);
int is_empty(void*);
void status_link(void *test);

#endif
