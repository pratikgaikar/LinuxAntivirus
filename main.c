#include"antivirus.h"


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
