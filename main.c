#include"antivirus.h"

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256

unsigned long *syscall_table = NULL; 
asmlinkage long (*original_open) (const char __user *, int, umode_t);
asmlinkage long (*original_execve) (const char __user *, const char __user *, const char __user *);

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
	printk("Kernel version: %s\n", kernel_version);
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
				printk("syscall_table retrieved\n");

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


int start_scan(char *path)
{
	int ret = 0;
	printk("\nAntivirus started ------->");	
	if(path!=NULL)	
		ret = check_for_virus(path);
	return ret;
}

asmlinkage long new_open(const char __user * path, int flags, umode_t mode) {
	
	char *buffer = NULL;
	buffer = kzalloc(PAGE_SIZE,GFP_KERNEL);
	buffer[0] = '\0';	
	copy_from_user(buffer, path, 4096);
	if(buffer != NULL && strstr(buffer, "pratik"))
	{
		printk("\nOpen hooked for file %s", buffer);
		start_scan(buffer);
	}	
	if(buffer)
		kfree(buffer);
	
	return original_open(path, flags, mode);
}

asmlinkage long new_execve(const char __user * path, const char __user * argv, const char __user * envp) {
	printk("execve() hooked\n");
	return original_execve(path, argv, envp);
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
			syscall_table[__NR_execve] = (unsigned long) &new_execve;
			syscall_table[__NR_open] = (unsigned long) &new_open;
			write_cr0(read_cr0() | 0x10000);
			printk("sys_call_table hooked successfully\n");
		} 
		else {
			printk("syscall_table is NULL\n");
		}
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
		write_cr0(read_cr0() | 0x10000);

		printk("sys_call_table unhooked successfully\n");
	} 
	else {
		printk("syscall_table is NULL\n");
	}	
}

MODULE_LICENSE("GPL");

module_init(antivirus_init);

module_exit(antivirus_exit);
