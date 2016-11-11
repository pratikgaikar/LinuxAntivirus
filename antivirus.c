#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
//#include <linux/crypto.h>
//#include <linux/scatterlist.h>
#include <linux/list.h>
#include <linux/string.h>
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

/*void status_link(void *test)
{
	struct node * it = head;
	
	while(it != NULL){
		printk(" \n %s------>", it->dir->d_iname);
			it = it->next;
	remove this
	}
}*/

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

	if(head == rear) {
		head = rear = NULL;
	}	
	else
		head = head->next;
	
	dir = my_current->dir;
	
	if(my_current)        
		kfree(my_current);
	
	return dir;
}

int is_empty(void *test)
{
	if(head==NULL)
		return 0;
	else
		return -1;
}

/*int check_for_virus(char *filename)
{
	int err = 0, offset = 0;
	struct file *black_list= NULL, *white_list =NULL, *input_file = NULL;
	char *buff = NULL;
		
	black_list = filp_open("/etc/antivirusfiles/blacklist", O_RDONLY, 0);
        
	if(IS_ERR(black_list)) {
                printk("\nError in black list file open");
		goto out;
        }

	white_list = filp_open("/etc/antivirusfiles/whitelist", O_RDONLY, 0);
        if(IS_ERR(white_list)) {
                printk("\nError white_list in file open");
		goto out;
        }

	input_file = filp_open(filename, O_RDONLY, 0);
        if(IS_ERR(input_file)) {
                printk("\nError in input file open");
		goto out;
        }
	
	int i_size = i_size_read(file_inode(input_file));
	
	while(offset < i_size)
	{
		
	}

	out:	
	if(black_list)	
		filp_close(black_list,NULL);	
	
	if(white_list)	
		filp_close(white_list,NULL);

	if(input_file)	
		filp_close(input_file,NULL);	

	return err;
}*/

void iterate_over_files(struct dentry *thedentry)
{
	struct dentry * curdentry = NULL;
	
	char *pathname = NULL, *finalpath = NULL;

	list_for_each_entry(curdentry, &thedentry->d_subdirs, d_child) 
	{
		if(S_ISREG(curdentry->d_inode->i_mode)) {
			pathname = kzalloc(4096, GFP_KERNEL);
       			finalpath = dentry_path_raw(curdentry, pathname, 4096);
			printk("Regular file Pathname %s",finalpath);	
			kfree(pathname);     			
			
        	}
		else if(S_ISDIR(curdentry->d_inode->i_mode)){
           		pathname = kzalloc(4096, GFP_KERNEL);
       			finalpath = dentry_path_raw(curdentry, pathname, 4096);
			printk("Regular file Pathname %s",finalpath);	
			add_new_node(curdentry);
			kfree(pathname);                 
        	}		
	}
}

static int __init antivirus_init(void)
{
	struct file *fi = NULL;
	struct dentry * thedentry = NULL;
	
	fi = filp_open("/usr/src/testdir", O_RDONLY, 0);
	
	thedentry = fi->f_path.dentry;

	add_new_node(thedentry);
	
	while( is_empty(NULL)!= 0)
	{
		iterate_over_files(delete_node(NULL));
	}
	
	if(fi)	
		filp_close(fi, NULL);	

	return 0;
}

static void __exit antivirus_exit(void)
{
	printk(KERN_INFO "Goodbye, world 2\n");
}

module_init(antivirus_init);

module_exit(antivirus_exit);
