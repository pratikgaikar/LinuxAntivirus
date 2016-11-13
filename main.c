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
#include "linkedlist.h"

extern void add_new_node(struct dentry *dir);
extern struct dentry *delete_node(void*);
extern int is_empty(void*);

int remove_garbage_value(char *data, int pagesize)
{
        int i= strlen(data)-1;
        if(data[i]!='\n' || data[i]!='\0')
        {
                while(i>0)
                {
                        if(data[i]=='\n' || data[i] == '\0')
                                break;
                        i--;
                }
        }
        if(i < pagesize && data[i]!='\0')
                data[++i]='\0';
        return strlen(data);
}

int read_file(struct file* file, char* data, int size) {
        int ret;
        mm_segment_t oldfs;
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        ret = vfs_read(file, data, size , &file->f_pos);
        set_fs(oldfs);
        return ret;
}

int check_for_virus(char *filename)
{
	int err = 0,ret = 0, read_bytes = 0, virusflag =0, read_bytes1 = 0, i_size = 0, i_size1= 0;
	struct file *black_list= NULL, *white_list =NULL, *input_file = NULL;
	int file_seek_position = 0;
	char *black_list_buff = NULL, *virusname = NULL , *parse_virus= NULL, *input_file_buffer= NULL;
	
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

	input_file_buffer = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(input_file_buffer == NULL)
	{
		err = -ENOMEM;
		goto out;
	}

	i_size = i_size_read(file_inode(black_list));
	i_size1 = i_size_read(file_inode(input_file));
	
	while(i_size > 0 )
	{
		if(black_list_buff == NULL || strlen(black_list_buff) == 0)
		{		
			black_list_buff = kmalloc(PAGE_SIZE,GFP_KERNEL);
			read_bytes = read_file(black_list, black_list_buff, 35);
			file_seek_position += remove_garbage_value(black_list_buff, 35);
        		black_list->f_pos = file_seek_position;	
			i_size -= strlen(black_list_buff);	
		}
			
		parse_virus = strsep(&black_list_buff,"\n");
		
		virusname = strsep(&parse_virus,",");

		printk("\n Virus Name %s",virusname);

		printk("\n Virus content %s", parse_virus);
		
		/*while(i_size1 > 0 )
		{			
			input_file_buffer[0]='\0';
			read_bytes1 = read_file(input_file, input_file_buffer, 35);
			printk("\nInput_file_buffer -\n%s", input_file_buffer);			
			if(strstr(parse_virus,input_file_buffer)!= NULL)
			{
				printk("\t Virus file.");
				virusflag = 1;				
				goto out;				
			}	
			i_size1 -= read_bytes1;	
		}*/					
	}

	out:	
	if(virusflag == 1)
		//Code for rename file to .virus.
	if(black_list)	
		filp_close(black_list,NULL);	
	
	if(white_list)	
		filp_close(white_list,NULL);

	if(input_file)
		filp_close(input_file,NULL);	

	if(input_file_buffer)
		kfree(input_file_buffer);
	return err;
}

void iterate_over_files(struct dentry *thedentry)
{
	struct dentry * curdentry = NULL;
	
	char *pathname = NULL, *finalpath = NULL;

	list_for_each_entry(curdentry, &thedentry->d_subdirs, d_child) 
	{
		if(S_ISREG(curdentry->d_inode->i_mode)) {
			pathname = kzalloc(4096, GFP_KERNEL);
       			finalpath = dentry_path_raw(curdentry, pathname, 4096);
			printk("\nRegular file Pathname %s",finalpath);
			check_for_virus(finalpath);	
			kfree(pathname);     			
			
        	}
		else if(S_ISDIR(curdentry->d_inode->i_mode)){
           		pathname = kzalloc(4096, GFP_KERNEL);
       			finalpath = dentry_path_raw(curdentry, pathname, 4096);
			printk("\nDir Pathname %s",finalpath);	
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
	printk("ROOT ---- >%s",thedentry->d_iname);

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

MODULE_LICENSE("GPL");

module_init(antivirus_init);

module_exit(antivirus_exit);
