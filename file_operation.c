#include"antivirus.h"

int remove_garbage_value(char *data, int recordsize)
{
	int i= recordsize-1;
        if(data[i]!='\n' && data[i]!='\0')
        {
                while(i>0)
                {
                        if(data[i]=='\n' || data[i] == '\0')
                                break;
                        i--;
                }
        }
        if((i+1) < PAGE_SIZE && data[i]!='\0')
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
	struct inode *temp_inode = d_inode(temp_dentry);    
	
	ret=vfs_rename(temp_parent, temp_dentry, output_parent, output_dentry, NULL, 0);	
	temp_inode->i_mode = temp_inode->i_mode & 0000;
        vfs_unlink(output_parent, output_dentry, NULL);
        return ret;
}

