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
 * Head points to the first node in the linked list.
 */
struct node *head=NULL;
struct node *rear=NULL;

/*
 *function prototype
 */

void add_new_node(struct dentry *dir);
struct dentry *delete_node(void*);
bool is_empty(void*);


#endif
