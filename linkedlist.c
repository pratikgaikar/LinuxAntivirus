#include"antivirus.h"

//Linked list implementation of Queue

struct node *head = NULL;
struct node *rear = NULL;

int is_empty(void *test)
{
	if(head==NULL)
		return 0;
	else
		return -1;
}

void add_new_node(struct dentry *dir)
{
        struct node * node = kmalloc(sizeof(struct node), GFP_KERNEL);
        node->dir = dir;
        node->next = NULL;
        if(head == NULL) {
                head = rear = node;
	}
	else {
		rear->next=node;
		rear=node;
	}
}

struct dentry *delete_node(void *test)
{
	struct node *my_current = NULL;
	struct dentry *dir = NULL;
        if(head == NULL) {
		 return dir;
	}

	my_current = head;

	if(head == rear) 
		head = rear = NULL;
	else
		head = head->next;
	
	dir = my_current->dir;
	
	if(my_current)        
		kfree(my_current);
	
	return dir;
}

void status_link(void *test)
{
	struct node * it = head;
	
	while(it != NULL){
		printk(" \n %s------>", it->dir->d_iname);
			it = it->next;
	}
}


