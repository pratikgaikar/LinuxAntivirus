#include"antivirus.h"

/*
 * Input:
 * Functionality: returns a hex value for given byte string seperated by white spaces
 */
unsigned char gethex(const char *s, char **endptr)
{
	char ch;
	while (isspace(*s)) s++;
	ch = strtoul(s, endptr, 16);
	return ch;
}

char *convert(const char *s, int *length)
{
	unsigned char *answer = kmalloc(((strlen(s) + 1) / 3) + 1, GFP_KERNEL);
	unsigned char *p;
	for (p = answer; *s; p++)
	{
		*p = gethex(s, (char **)&s);
	}
	*length = p - answer;
	return answer;
}


bool check_in_blacklist(struct file * input_file,struct file * blacklist_file)
{
	int read_blacklist_bytes = 0,read_file_bytes = 0, blacklist_size = 0, file_size= 0, original_file_size=0;
	bool virus_flag = false;
	int blacklist_fp = 0, hex_in_char_len=0;
	char *black_list_work_buff = NULL, *black_list_init_buff = NULL, *virus_name = NULL , *parse_virus= NULL, *input_file_buff= NULL;
	char *hex_in_char_ptr=NULL;
	
	input_file_buff = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(input_file_buff == NULL)
	{
		//err = -ENOMEM;
		goto out;
	}
	input_file_buff[0]='\0';
	blacklist_size = i_size_read(file_inode(blacklist_file));
	original_file_size = i_size_read(file_inode(input_file));
	black_list_init_buff = kmalloc(PAGE_SIZE,GFP_KERNEL);
	black_list_init_buff[0]='\0';
	while(blacklist_size > 0 )
	{		
		if(black_list_work_buff == NULL || strlen(black_list_work_buff) == 0)
		{
			black_list_work_buff = black_list_init_buff;
			read_blacklist_bytes = read_file(blacklist_file, black_list_work_buff, 35);
			blacklist_fp += remove_garbage_value(black_list_work_buff, 35);
        		blacklist_file->f_pos = blacklist_fp;
			blacklist_size -= strlen(black_list_work_buff);	
		}
			
		if(black_list_work_buff != NULL)
			parse_virus = strsep(&black_list_work_buff,"\n");
		
		if(parse_virus !=NULL)		
			virus_name = strsep(&parse_virus,",");
		
		if(parse_virus !=NULL)	
		{
			hex_in_char_ptr=convert(parse_virus, &hex_in_char_len);
			hex_in_char_ptr[hex_in_char_len]='\0';
		}
	
		file_size=original_file_size;
		input_file->f_pos=0;

		while(file_size > 0 )
		{			
			read_file_bytes = read_file(input_file, input_file_buff, 35);
			//printk("Input_file_buffer:%s\n", input_file_buff);
			if(strstr(input_file_buff, hex_in_char_ptr)!= NULL)
			{
				//printk("This is a Virus file\n");
				//printk("Virus found %s\n",virus_name); 
				virus_flag = true;				
				goto out;				
			}
			if(input_file->f_pos!=original_file_size)
			{
				//printk("Read 35 bytes\n");
				//printk("1-File position is :%d\n",input_file->f_pos);
				input_file->f_pos -= (hex_in_char_len);
				file_size = file_size - read_file_bytes + (hex_in_char_len);
			}
			else
			{
				//printk("less than 35 bytes read\n");
				file_size -= read_file_bytes;
				//printk("2-File position is :%d\n",input_file->f_pos);
			}
			input_file_buff[0]='\0';
		}
		//printk("This Virus %s was not found\n",virus_name); 
		if(hex_in_char_ptr)
			kfree(hex_in_char_ptr);			
	}

	out:	
			
	
	if(input_file_buff)
		kfree(input_file_buff);

	if(black_list_init_buff)
		kfree(black_list_init_buff);

	return virus_flag;
}

