#include"antivirus.h"

#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256
#define MYPROTO NETLINK_USERSOCK
#define MYGRP 21

static struct sock *nl_sk = NULL;
unsigned long *syscall_table = NULL; 
asmlinkage long (*original_open) (const char __user *, int, umode_t);
asmlinkage long (*original_execve) (const char __user *, const char __user *, const char __user *);

asmlinkage long (*original_execveat) (int, const char __user *, const char __user *, const char __user *, int);
asmlinkage long (*original_open_by_handle_at) (int, struct file_handle __user *, int);
asmlinkage long (*original_openat) (int, const char __user *, int, umode_t);

/* send virus file name to user*/
static void send_to_user(char *msg)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(msg) + 1;
    int res;
    skb = nlmsg_new(NLMSG_ALIGN(msg_size + 1), GFP_KERNEL);
    if (!skb) {
        pr_err("Allocation failure.\n");
        return;
    }
    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size + 1, 0);
    strcpy(nlmsg_data(nlh), msg);    
    res = nlmsg_multicast(nl_sk, skb, 0, MYGRP, GFP_KERNEL);
    if (res < 0)
        pr_info("nlmsg_multicast() error: %d\n", res);
    else
        pr_info("Success.\n");
}

char *acquire_kernel_version (char *buf) {
	struct file *proc_version = NULL;
	char *kernel_version = NULL;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs (KERNEL_DS);
	
	proc_version = filp_open(PROC_V, O_RDONLY, 0);
	if (IS_ERR(proc_version) || (proc_version == NULL)) {
	    return NULL;
	}

	vfs_read(proc_version, buf, MAX_VERSION_LEN, &(proc_version->f_pos));
	kernel_version = strsep(&buf, " ");
	kernel_version = strsep(&buf, " ");
	kernel_version = strsep(&buf, " ");

	if(proc_version != NULL) {
		filp_close(proc_version, 0);
	}
	set_fs(oldfs);
	return kernel_version;
}

int find_sys_call_table (char *kern_ver)
{
	unsigned long temp = 0;	
	char *system_map_entry = NULL;
	int i = 0, ret = 0;
	char *filename = NULL;
	size_t filename_length = strlen(kern_ver) + strlen(BOOT_PATH) + 1;
	struct file *f = NULL;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs (KERNEL_DS);

	if(kern_ver == NULL) {
		printk("acquiring kernel version failed\n");
		ret = -1;
		goto out;
	}

	filename = kzalloc(filename_length, GFP_KERNEL);
	if (filename == NULL) {
		printk("kmalloc failed on System.map-<version> filename allocation\n");
		ret = -1;
		goto out;
	}
	filename[0] = '\0';
	strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
	strncat(filename, kern_ver, strlen(kern_ver));

	f = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(f) || (f == NULL)) {
		printk("Error opening System.map-<version> file: %s\n", filename);
		ret = -1;
		goto out;
	}

	system_map_entry = kzalloc(MAX_VERSION_LEN, GFP_KERNEL);
	if (system_map_entry == NULL) {
		printk("kmalloc failed on System.map-<version> map entry allocation\n");
		ret = -1;
		goto out;
	}
	system_map_entry[0] = '\0';

	while (vfs_read(f, system_map_entry + i, 1, &f->f_pos) == 1) {
		if ( system_map_entry[i] == '\n' || i == MAX_VERSION_LEN ) {
			i = 0;
			if (strstr(system_map_entry, "sys_call_table") != NULL) {
				char *sys_string;
				char *system_map_entry_ptr = system_map_entry;

				sys_string = kzalloc(MAX_VERSION_LEN, GFP_KERNEL);
				if (sys_string == NULL) { 
					printk("kmalloc failed on sys_string allocation\n");
					ret = -1;
					goto out;				
				}
				sys_string[0] = '\0';

				strncpy(sys_string, strsep(&system_map_entry_ptr, " "), MAX_VERSION_LEN);
				kstrtoul(sys_string, 16, &temp);
				syscall_table = (unsigned long *) temp;
				kfree(sys_string);
				break;
				}

				system_map_entry[0] = '\0';
				continue;
		}
		i++;
	}

out:	if(f != NULL) {
		filp_close(f, 0);
	}
	if(filename != NULL) {
		kfree(filename);
	}
	if(system_map_entry != NULL) {
		kfree(system_map_entry);
	}
	set_fs(oldfs);
	return ret;
}

int start_scan(char *path,int flags)
{
	int ret = 0;
	if(path!=NULL)	
		ret = check_for_virus(path,flags);
	return ret;
}

asmlinkage long new_open(const char __user * path, int flags, umode_t mode) {
	
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, path, 4096);
	//printk("Open hooked for file %s\n", buffer);
	//if(buffer != NULL && strstr(buffer, "pratik"))
	//if( strstr(buffer,"dev") == NULL && (strstr(buffer,"lib") == NULL)) 
	{
		//printk("Open hooked for file %s\n", buffer);
		ret = start_scan(buffer,flags);
		
	}	
	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);
		return original_open(path, flags, mode);
	}	
	else if(ret == -10)
	{
		send_to_user(buffer); // send using socket
	}
	if(buffer)
		kfree(buffer);
	return -EBADF;
}

asmlinkage long new_execve(const char __user * path, const char __user * argv, const char __user * envp) {
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, path, 4096);
	
	printk("Execve hooked for file %s\n", buffer);
	ret = start_scan(buffer,O_RDONLY);
	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);
		return original_execve(path, argv, envp);
	}	
	else if(ret == -10)
	{
		send_to_user(buffer); // send using socket
	}
	if(buffer)
		kfree(buffer);
	return -EBADF;
}

asmlinkage long new_execveat(int dfd, const char __user *filename, const char __user *argv, const char __user *envp, int flags) {
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, filename, 4096);
	
	printk("Execveat hooked for file %s\n", buffer);
	ret = start_scan(buffer,O_RDONLY);

	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);
		return original_execveat(dfd, filename, argv, envp, flags);
	}	
	else 
	{
		send_to_user(buffer); // send using socket
		if(buffer)
			kfree(buffer);
		return -EBADF;
	}
}

asmlinkage long new_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags) {
	//printk("New Open By Handle At hooked\n");
	return original_open_by_handle_at(mountdirfd, handle, flags);
}

asmlinkage long new_openat(int dfd, const char __user *filename, int flags, umode_t mode) {
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, filename, 4096);
	//printk("Open hooked for file %s\n", buffer);
	if(buffer != NULL && strstr(buffer, "pratik"))
	//if( strstr(buffer,"dev") == NULL && (strstr(buffer,"lib") == NULL)) 
	{
		//printk("Open hooked for file %s\n", buffer);
		ret = start_scan(buffer,flags);
		
	}	
	if(ret == 0)
	{
		if(buffer)
		kfree(buffer);
		return original_openat(dfd, filename, flags, mode);
	}	
	else 
	{
		send_to_user(buffer); // send using socket
		if(buffer)
		kfree(buffer);
		return -EBADF;
	}
}

static int __init antivirus_init(void)
{
	int syscall_table_success = 0;
	char *kernel_version = NULL;
	kernel_version = kzalloc(MAX_VERSION_LEN, GFP_KERNEL);
	kernel_version[0] = '\0';

	syscall_table_success = find_sys_call_table(acquire_kernel_version(kernel_version));	
	if(syscall_table_success == -1) {
		printk("syscall table address retrieval failed:\n");
		goto out;
	}
	else {
			
		if (syscall_table != NULL) {
			write_cr0(read_cr0() & (~0x10000));
			original_open = (void *)syscall_table[__NR_open];
			original_execve = (void *)syscall_table[__NR_execve];

			//original_execveat = (void *)syscall_table[__NR_execveat];
			//original_open_by_handle_at = (void *)syscall_table[__NR_open_by_handle_at];

			//original_perf_event_open = (void *)syscall_table[__NR_perf_event_open];
			//original_openat = (void *)syscall_table[__NR_openat];
			
			syscall_table[__NR_execve] = (unsigned long) &new_execve;
			syscall_table[__NR_open] = (unsigned long) &new_open;

			//syscall_table[__NR_execveat] = (unsigned long) &new_execveat;
			//syscall_table[__NR_open_by_handle_at] = (unsigned long) &new_open_by_handle_at;

			//syscall_table[__NR_perf_event_open] = (unsigned long) &new_perf_event_open;
			//syscall_table[__NR_openat] = (unsigned long) &new_openat;
			write_cr0(read_cr0() | 0x10000);
			printk("sys_call_table hooked successfully\n");
		} 
		else {
			printk("syscall_table is NULL\n");
		}
	}
	
	nl_sk = netlink_kernel_create(&init_net, MYPROTO, NULL);
    	if (!nl_sk) {
        	pr_err("Error creating socket.\n");
        	return -10;
    	}
out:	
	if(kernel_version != NULL) {
		kfree(kernel_version);
	}
	return 0;	
}

static void __exit antivirus_exit(void)
{
	if (syscall_table != NULL) {	   
		write_cr0(read_cr0() & (~0x10000));
		syscall_table[__NR_open] = (unsigned long)original_open;
		syscall_table[__NR_execve] = (unsigned long)original_execve;

		//syscall_table[__NR_execveat] = (unsigned long) &original_execveat;
		//syscall_table[__NR_open_by_handle_at] = (unsigned long) &original_open_by_handle_at;

		//syscall_table[__NR_perf_event_open] = (unsigned long) &original_perf_event_open;
		//syscall_table[__NR_openat] = (unsigned long) &original_openat;
		write_cr0(read_cr0() | 0x10000);

		printk("sys_call_table unhooked successfully\n");
	} 
	else {
		printk("syscall_table is NULL\n");
	}	
	send_to_user("EXIT"); // send using socket
	netlink_kernel_release(nl_sk);
}

MODULE_LICENSE("GPL");

module_init(antivirus_init);

module_exit(antivirus_exit);
