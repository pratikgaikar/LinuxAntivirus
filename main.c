#include"antivirus.h"

static struct sock *nl_sk = NULL;
unsigned long *syscall_table = NULL; 
asmlinkage long (*original_open) (const char __user *, int, umode_t);
asmlinkage long (*original_execve) (const char __user *, const char __user *, const char __user *);
asmlinkage long (*original_execveat) (int, const char __user *, const char __user *, const char __user *, int);
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
        pr_err("Allocation failure\n");
        return;
    }
    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size + 1, 0);
    strcpy(nlmsg_data(nlh), msg);    
    res = nlmsg_multicast(nl_sk, skb, 0, GRP, GFP_KERNEL);   
}

/* Get current kernel version from /proc/version file*/
char *get_kernel_version (char *buffer) {
	struct file *proc_version_file = NULL;
	char *kernel_version = NULL;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs (KERNEL_DS);
	
	proc_version_file = filp_open(PROC_VERSION, O_RDONLY, 0);
	if (proc_version_file == NULL || IS_ERR(proc_version_file)) {
	    return NULL;
	}

	vfs_read(proc_version_file, buffer, MAX_KERNEL_VERSION_LEN, &(proc_version_file->f_pos));
	kernel_version = strsep(&buffer, " ");
	kernel_version = strsep(&buffer, " ");
	kernel_version = strsep(&buffer, " ");

	if(proc_version_file != NULL) {
		filp_close(proc_version_file, 0);
	}

	set_fs(oldfs);
	return kernel_version;
}

/*Get the system call table address from the /boot/System.map-<version> file*/
int find_sys_call_table_address (char *kernel_version)
{
	unsigned long temp = 0;	
	char *system_map_entry = NULL;
	int i = 0;
	int retval = 0;
	char *filename = NULL;
	size_t filename_length = strlen(kernel_version) + strlen(KERNEL_BOOT_PATH) + 1;
	struct file *file = NULL;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs (KERNEL_DS);

	if(kernel_version == NULL) {
		printk("Kernel Version is null\n");
		retval = -1;
		goto out;
	}

	filename = kzalloc(filename_length, GFP_KERNEL);
	if (filename == NULL) {
		printk("Memory allocation failed for System.map filename\n");
		retval = -1;
		goto out;
	}
	filename[0] = '\0';
	strncpy(filename, KERNEL_BOOT_PATH, strlen(KERNEL_BOOT_PATH));
	strncat(filename, kernel_version, strlen(kernel_version));

	file = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(file) || (file == NULL)) {
		printk("Error opening System.map-<version> file: %s\n", filename);
		retval = -1;
		goto out;
	}

	system_map_entry = kzalloc(MAX_KERNEL_VERSION_LEN, GFP_KERNEL);
	if (system_map_entry == NULL) {
		printk("Memory allocation failed for system map entry allocation\n");
		retval = -1;
		goto out;
	}
	system_map_entry[0] = '\0';

	while (vfs_read(file, system_map_entry + i, 1, &file->f_pos) == 1) {
		if ( system_map_entry[i] == '\n' || i == MAX_KERNEL_VERSION_LEN ) {
			i = 0;
			if (strstr(system_map_entry, "sys_call_table") != NULL) {
				char *temp_string = NULL;
				char *system_map_entry_ptr = system_map_entry;

				temp_string = kzalloc(MAX_KERNEL_VERSION_LEN, GFP_KERNEL);
				if (temp_string == NULL) { 
					printk("Memory Allocation failed for sys_string allocation\n");
					retval = -1;
					goto out;				
				}
				temp_string[0] = '\0';

				strncpy(temp_string, strsep(&system_map_entry_ptr, " "), MAX_KERNEL_VERSION_LEN);
				kstrtoul(temp_string, 16, &temp);
				syscall_table = (unsigned long *) temp;

				if(temp_string != NULL) {
					kfree(temp_string);
				}

				break;
			}

				system_map_entry[0] = '\0';
				continue;
		}
		i++;
	}

out:	if(file != NULL) {
		filp_close(file, 0);
	}
	if(filename != NULL) {
		kfree(filename);
	}
	if(system_map_entry != NULL) {
		kfree(system_map_entry);
	}
	set_fs(oldfs);
	return retval;
}

/*Starts scanning of the file by invoking the check_for_virus function*/
int start_scan(char *path,int flags, umode_t mode)
{
	int ret = 0;
	if(path!=NULL)	
		ret = check_for_virus(path,flags, mode);
	return ret;
}

/*This method intercepts the original open system call. It scans the file for any virus and takes the appropriate actions*/
asmlinkage long new_open(const char __user * path, int flags, umode_t mode) {
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, path, 4096);
	if(flags > 32768 || strstr(buffer,"/proc") != NULL) {
		if(buffer)
			kfree(buffer);	
		return original_open(path, flags, mode);
	}
	
	ret = start_scan(buffer,flags,mode);   // scan input file for virus.
	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);
		return original_open(path, flags, mode);  //return original open
	}	
	else if(ret == -10)
	{
		send_to_user(buffer); // send using socket
	}
	
	if(buffer)
		kfree(buffer);
	return -EBADF;	 //return bad file descriptor.
}

/*This method intercepts the original execve system call. It scans the file for any virus and takes the appropriate actions*/
asmlinkage long new_execve(const char __user * path, const char __user * argv, const char __user * envp) {
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, path, 4096);
	
	ret = start_scan(buffer,O_RDONLY,0);   // scan input file for virus.
	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);
		return original_execve(path, argv, envp);  //return original execve
	}	
	else if(ret == -10)
	{
		send_to_user(buffer); // send using socket
	}
	
	if(buffer)
		kfree(buffer);
	return -EBADF;    //return bad file descriptor.
}

/*This method intercepts the original openat system call. It scans the file for any virus and takes the appropriate actions*/
asmlinkage long new_openat(int dfd, const char __user *filename, int flags, umode_t mode) {
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, filename, 4096);

	if(flags > 32768 || strstr(buffer,"/proc")) {
		if(buffer)
			kfree(buffer);		
		return original_openat(dfd, filename, flags, mode);
	}
	
	ret = start_scan(buffer,flags,mode);  // scan input file for virus.
	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);
		return original_openat(dfd, filename, flags, mode);  //return original openat
	}	
	else if(ret == -10)
	{
		send_to_user(buffer); // send using socket
	}
	
	if(buffer)
		kfree(buffer); 
	return -EBADF;	  //return bad file descriptor.
}

/*This method intercepts the original execveat system call. It scans the file for any virus and takes the appropriate actions*/
asmlinkage long new_execveat(int dfd, const char __user *filename, const char __user *argv, const char __user *envp, int flags) {
	
	int ret = 0;	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, filename, 4096);
	printk("Execveat opened for file: %s\n",buffer);
	ret = start_scan(buffer,O_RDONLY,0);   // scan input file for virus.
	if(ret == 0)
	{
		if(buffer)
			kfree(buffer);		
		return original_execveat(dfd, filename, argv, envp, flags);   //return original execveat
	}	
	else if(ret == -10)
	{
		send_to_user(buffer); // send using socket
	}
	
	if(buffer)
		kfree(buffer);
	return -EBADF;     //return bad file descriptor.		
}


/* This function initializes the module. It disables the kernel write protection using CR0 register thus disabling the read only system call table address*/
/* It stores the original addresses of the system calls first and then write the address of our new intercepted functions over the address of the original system call functions*/
/* It also initiates the socket connection between the user and kernel space*/ 
static int __init antivirus_init(void)
{
	int syscall_table_success = 0;
	char *kernel_version = NULL;
	kernel_version = kzalloc(MAX_KERNEL_VERSION_LEN, GFP_KERNEL);
	kernel_version[0] = '\0';

	syscall_table_success = find_sys_call_table_address(get_kernel_version(kernel_version));	
	if(syscall_table_success == -1) {
		printk("syscall table address retrieval failed:\n");
		goto out;
	}
	else {
			
		if (syscall_table != NULL) {
			write_cr0(read_cr0() & (~0x10000));  //set the Write Protect Bit (16th bit in CR0 register) to disable the write protection
			original_open = (void *)syscall_table[__NR_open];
			original_execve = (void *)syscall_table[__NR_execve];
			original_execveat = (void *)syscall_table[__NR_execveat];
			original_openat = (void *)syscall_table[__NR_openat];
			syscall_table[__NR_execve] = (unsigned long) &new_execve;   
			syscall_table[__NR_open] = (unsigned long) &new_open;
			syscall_table[__NR_execveat] = (unsigned long) &new_execveat;
			syscall_table[__NR_openat] = (unsigned long) &new_openat;
			write_cr0(read_cr0() | 0x10000);	//set the Write Protect Bit (16th bit in CR0 register) to again enable the write protection		
		} 		
	}
	
	nl_sk = netlink_kernel_create(&init_net, PROTOCOL, NULL);
    	if (!nl_sk) {
        	pr_err("Error creating socket.\n");
        	return -10;
    	}

	send_to_user("INSTALLED_ANTIVIRUS"); // send using socket
out:	
	if(kernel_version != NULL) {
		kfree(kernel_version);
	}
	return 0;	
}

/* This function is called when module exits. It disables the kernel write protection using CR0 register thus disabling the read only system call table address*/
/* It restores the original addresses of the system calls*/
/* It also terminates the socket connection between the user and kernel space*/ 
static void __exit antivirus_exit(void)
{
	if (syscall_table != NULL) {	   
		write_cr0(read_cr0() & (~0x10000));    // set the Write Protect Bit (16th bit in CR0 register) to disable the write protection
		syscall_table[__NR_open] = (unsigned long)original_open;
		syscall_table[__NR_execve] = (unsigned long)original_execve;
		syscall_table[__NR_execveat] = (unsigned long) original_execveat;
		syscall_table[__NR_openat] = (unsigned long) original_openat;
		write_cr0(read_cr0() | 0x10000);	//set the Write Protect Bit (16th bit in CR0 register) to again enable the write protection
	} 
	else {
		printk("syscall_table is NULL\n");
	}	
	send_to_user("EXIT"); // send using socket
	netlink_kernel_release(nl_sk); //release socket.
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PRATIK GAIKAR");	
module_init(antivirus_init);
module_exit(antivirus_exit);
