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
        struct dir_struct *dir_struct;
        struct node * next;
};

struct dir_struct{
	struct dentry *dir;
	char *dir_path;
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
	
	}
}*/

void add_new_node(struct dir_struct *dir)
{
        struct node * node = kmalloc(sizeof(struct node), GFP_KERNEL);
        node->dir_struct = dir;
        node->next = NULL;
        if(head == NULL) {
                head = rear = node;
	}
	else {
		rear->next=node;
		rear=node;
	}
}

struct dir_struct *delete_node(void *test)
{
	struct node *my_current = NULL;
	struct dir_struct *dir = NULL;
        if(head == NULL) {
		 return dir;
	}

	my_current = head;

	if(head == rear) {
		head = rear = NULL;
	}	
	else
		head = head->next;
	
	dir = my_current->dir_struct;
	
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

int check_for_virus(char *filename)
{
	int err = 0, offset = 0;
	struct file *black_list= NULL, *white_list =NULL, *input_file = NULL, char *buff = NULL;
		
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
	
	i_size = i_size_read(file_inode(file));
	
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
}

void iterate_over_files(struct dir_struct *dir_struct)
{
	struct dentry * curdentry = NULL;
	struct dir_struct *sub_dir_struct = NULL;
	char *full_path = NULL;

	struct dentry *thedentry = dir_struct->dir;

	list_for_each_entry(curdentry, &thedentry->d_subdirs, d_child) 
	{
		if(S_ISREG(curdentry->d_inode->i_mode)) {
			
			int filelen = strlen(dir_struct->dir_path) + strlen(curdentry->d_iname) + 2;
			full_path = kmalloc(filelen, GFP_KERNEL);
			strcpy(full_path,dir_struct->dir_path);
			strcat(full_path,"/");
			strcat(full_path,curdentry->d_iname);
			full_path[filelen-1]='\0';
			printk("\nRegular File ---->%s",full_path);	
			
        	}
		else if(S_ISDIR(curdentry->d_inode->i_mode)){
           		
			sub_dir_struct = kmalloc(sizeof(struct dir_struct),GFP_KERNEL);
			sub_dir_struct->dir = curdentry;
			int len = strlen(dir_struct->dir_path) + strlen(curdentry->d_iname) + 2;
			sub_dir_struct->dir_path = kmalloc(len,GFP_KERNEL);
			strcpy(sub_dir_struct->dir_path,dir_struct->dir_path);
			strcat(sub_dir_struct->dir_path,"/");
			strcat(sub_dir_struct->dir_path,curdentry->d_iname);
			sub_dir_struct->dir_path[len-1]='\0';
			printk("\nDirectory ---->%s",sub_dir_struct->dir_path);			
			
			add_new_node(sub_dir_struct);                 
        	}		
	}
}

static int __init antivirus_init(void)
{
	struct file *fi = NULL;
	struct dentry * thedentry = NULL;
	struct dir_struct *dir_struct = NULL;

	dir_struct = kmalloc(sizeof(struct dir_struct),GFP_KERNEL);

	fi = filp_open("/usr/src/testdir", O_RDONLY, 0);
	
	thedentry = fi->f_path.dentry;

	dir_struct->dir = thedentry;
	
	dir_struct->dir_path = kmalloc(17,GFP_KERNEL);

	strncpy(dir_struct->dir_path,"/usr/src/testdir", 16);
	
	dir_struct->dir_path[16] = '\0';
	
	printk("Root Dir ---> %s", dir_struct->dir_path);
	
	add_new_node(dir_struct);
	
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
