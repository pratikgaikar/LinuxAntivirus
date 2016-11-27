#include"antivirus.h"

/*
 * Input: s: Pointer to a string which has hex bytes to be converted to char,
 * endptr: end pointer of the string
 * Functionality: returns a character for given bytes seperated by white spaces
 */
unsigned char gethex(const char *s, char **endptr)
{
	char ch;
	while (isspace(*s)) s++;
	ch = strtoul(s, endptr, 16);
	return ch;
}
/*
 * Input: s: String with bytes, to be converted to characters, char_in_hex: Output is 
 * written to this variable, length : length of the output.
 * Functionality: returns a character string for given bytes of string seperated by white spaces
 */
void convert(const char *s,char *char_in_hex, int *length)
{
    	unsigned char *answer = char_in_hex;
    	unsigned char *p;
	for (p = answer; *s; p++)
	{
		*p = gethex(s, (char **)&s);
	}
	*length = p - answer;
}

/*
 * Input: input_file : The file which is to be scanned for virus,  blacklist_file: The
 * file which has blacklist bytes
 * Functionality: Checks for virus, returns true if it has virus and false otherwise.
 */
bool check_in_blacklist(struct file * input_file,struct file * blacklist_file)
{
	int read_blacklist_bytes = 0,read_file_bytes = 0, blacklist_size = 0, file_size= 0, original_file_size=0;
	bool virus_flag = false;
	int blacklist_fp = 0, hex_in_char_len=0;
	char *black_list_work_buff = NULL, *black_list_init_buff = NULL, *parse_virus= NULL, *input_file_buff= NULL;
	char *hex_in_char_ptr=NULL, *virus_name=NULL;
	
	input_file_buff = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(input_file_buff == NULL)
	{
		goto out;
	}
	input_file_buff[0]='\0';
	blacklist_size = i_size_read(file_inode(blacklist_file));
	original_file_size = i_size_read(file_inode(input_file));
	black_list_init_buff = kmalloc(PAGE_SIZE,GFP_KERNEL);
	black_list_init_buff[0]='\0';

	hex_in_char_ptr = kmalloc(PAGE_SIZE,GFP_KERNEL);
    	hex_in_char_ptr[0]='\0';

    	while(blacklist_size > 0 || (black_list_work_buff!=NULL && strlen(black_list_work_buff) > 0))
    	{        
        	hex_in_char_ptr[0]='\0';        
        	if(black_list_work_buff == NULL || strlen(black_list_work_buff) == 0)
        	{
			black_list_work_buff = black_list_init_buff;
			read_blacklist_bytes = read_file(blacklist_file, black_list_work_buff, PAGE_SIZE);
			blacklist_fp += remove_garbage_value(black_list_work_buff, read_blacklist_bytes);
        		blacklist_file->f_pos = blacklist_fp;
			blacklist_size -= strlen(black_list_work_buff);
		}

		if(black_list_work_buff != NULL)
		{
			parse_virus = strsep(&black_list_work_buff,"\n");
		}
		else
		{
			goto out;
		}
		if(parse_virus !=NULL)		
		{
			virus_name = strsep(&parse_virus,",");	
		}
		else
		{
			goto out;
			
		}
		
		if(parse_virus !=NULL)    
        	{
            		convert(parse_virus,hex_in_char_ptr, &hex_in_char_len);
            		hex_in_char_ptr[hex_in_char_len]='\0';
        	}
		else
		{
			goto out;
		}

		file_size=original_file_size;
		input_file->f_pos=0;
		while(file_size > 0 )
		{			
			read_file_bytes = read_file(input_file, input_file_buff,  PAGE_SIZE-1);
			input_file_buff[read_file_bytes]='\0';
			if(strstr(input_file_buff, hex_in_char_ptr)!= NULL)
			{
				virus_flag = true;				
				goto out;				
			}
			if(input_file->f_pos!=original_file_size)
			{
				input_file->f_pos -= (hex_in_char_len);
				file_size = file_size - read_file_bytes + (hex_in_char_len);
			}
			else
			{
				file_size -= read_file_bytes;
				
			}
			input_file_buff[0]='\0';
		}		
	}

	out:	
	if(hex_in_char_ptr)
			kfree(hex_in_char_ptr);		
	
	if(input_file_buff)
		kfree(input_file_buff);

	if(black_list_init_buff)
		kfree(black_list_init_buff);

	return virus_flag;
}

