#include"antivirus.h"

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

int read_file(struct file* file, char *data, int size) {
        int ret;
        mm_segment_t oldfs;
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        ret = vfs_read(file, data, size , &file->f_pos);
        set_fs(oldfs);
        return ret;
}

int rename_file(struct file *temp_file, struct file *output_file)
{
	int ret =0;   
	struct dentry *temp_dentry = temp_file->f_path.dentry;
	struct dentry *output_dentry = output_file->f_path.dentry;
	struct inode *temp_parent = d_inode(temp_dentry->d_parent);
	struct inode *output_parent = d_inode(output_dentry->d_parent);    
	ret=vfs_rename(temp_parent, temp_dentry, output_parent, output_dentry, NULL, 0);
        vfs_unlink(output_parent, output_dentry, NULL);
        return ret;
}

