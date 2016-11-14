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
