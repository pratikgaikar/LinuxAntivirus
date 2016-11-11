#include"linkedlist.h"

//Linked list implementation of Queue
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
	struct node *my_current;
	struct dentry *dir = NULL;
        if(head == NULL) {
		 return dir;
	}
	my_current = head;
	if(head==rear) {
		rear=NULL;
	}	
	head = head->next;
	dir = my_current->dir;
        kfree(current);
	return dir;
}

bool is_empty(void *test)
{
	if(head==NULL)
		return true;
	else
		return false;
}

