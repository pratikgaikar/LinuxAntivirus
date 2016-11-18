#include"antivirus.h"
int check_for_virus(char *filename)
{
	int ret = 0;
	struct file *black_list= NULL, *input_file = NULL, *white_list = NULL, *virus_file = NULL;
	bool in_whitelist=false ,is_virus=false;
	char *virus_file_name = NULL;
	struct inode *inode;
	umode_t im;
	
	black_list = filp_open("/etc/antivirusfiles/blacklist", O_RDONLY, 0);
        if(IS_ERR(black_list)) {
		ret = PTR_ERR(black_list);
		printk("\nError in black list file open");
		black_list = NULL;		
		goto out;
        }

	white_list = filp_open("/etc/antivirusfiles/whitelist", O_RDONLY, 0);
        if(IS_ERR(white_list)) {
                printk("\nError in black list file open");
		ret = PTR_ERR(white_list);	
		white_list = NULL;
		goto out;
        }

	input_file = filp_open(filename, O_RDONLY, 0);
        if(IS_ERR(input_file)) {
                printk("\nError in input file open %s", filename);
		ret = PTR_ERR(input_file);
		input_file = NULL;
		goto out;
        }
	
	inode = file_inode(input_file);
    	if(inode != NULL)
	{    
        	im = inode->i_mode;
        	if(S_ISCHR(im) > 0)
		{
            		goto out;
        	}
        	if(S_ISBLK(im) > 0) 
		{
            		goto out;
        	}
    	}

	/* Check for whitelist*/
	in_whitelist=check_in_whitelist(input_file,white_list);
	if(in_whitelist)
	{
		printk("\n%sFOUND IN WHITELIST.", filename);		
		goto out;
	}
	/* Check for virus content */
	is_virus=check_in_blacklist(input_file,black_list);
	if(is_virus)
	{
		ret = -1;  /*set file as a virus file*/
		printk("\nVIRUS FOUND IN FILE %s", filename);
		virus_file_name = kzalloc(PAGE_SIZE,GFP_KERNEL);
		strcpy(virus_file_name,filename);
		strcat(virus_file_name,".virus");
		virus_file_name[strlen(virus_file_name)]='\0';
		/*virus_file = filp_open(virus_file_name, O_CREAT, 0);
        	if(IS_ERR(virus_file)) {
			ret = PTR_ERR(virus_file);
                	printk("\nError in black list file open");
			goto out;
   		}*/

		//rename the file.
		//rename_file(input_file,virus_file);			
		goto out;
	}
	else
	{
		printk("\n %s File is Good ",filename);
	}
out:	
	/*Close blacklist file */
	if(black_list != NULL)
		filp_close(black_list, NULL);

	/*Close whitelist file */
	if(white_list !=NULL)
		filp_close(white_list,NULL);

	/*Close input file */
	if(input_file !=NULL)
		filp_close(input_file,NULL);

	/*Free memory*/	
	if(virus_file_name !=NULL)
		kfree(virus_file_name);		
	return ret;
}
