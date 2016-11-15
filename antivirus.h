#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/init.h>		
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/string.h>
#include <stdbool.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include <linux/acpi.h>
#include <linux/ctype.h>

//Linked list implementation of Queue
struct node{
        struct dentry *dir;
        struct node * next;
};


/*
 *function prototype for linked list
 */
void add_new_node(struct dentry *dir);
struct dentry *delete_node(void*);
int is_empty(void*);
void status_link(void *test);


/*
 *function prototype for linked list
 */
int check_for_virus(char *filename);

/*
 *function prototype for whitelist operations.
 */
bool check_in_whitelist(struct file * input_file,struct file * white_list);

/*
 *function prototype for blacklist operations.
 */
bool check_in_blacklist(struct file * input_file,struct file * black_list);

/*
 *function prototype for file operations
 */
int remove_garbage_value(char *data, int pagesize);
int read_file(struct file* file, char *data, int size);
int rename_file(struct file *temp_file, struct file *output_file);
#endif