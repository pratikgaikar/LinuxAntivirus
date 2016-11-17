#include"antivirus.h"

int check_for_virus(char *filename)
{
	int err = 0;
	struct file *black_list= NULL, *input_file = NULL, *white_list = NULL, *virus_file = NULL;
	bool in_whitelist=false ,is_virus=false;
	char *virus_file_name = NULL;

	black_list = filp_open("/etc/antivirusfiles/blacklist", O_RDONLY, 0);
        if(IS_ERR(black_list)) {
		err = PTR_ERR(black_list);
                printk("\nError in black list file open");
		goto out;
        }

	white_list = filp_open("/etc/antivirusfiles/whitelist", O_RDONLY, 0);
        if(IS_ERR(white_list)) {
                printk("\nError in black list file open");
		err = PTR_ERR(white_list);	
		goto out;
        }

	input_file = filp_open(filename, O_RDONLY, 0);
        if(IS_ERR(input_file)) {
                printk("\nError in input file open");
		err = PTR_ERR(input_file);
		goto out;
        }

	/* Check for whitelist*/
	in_whitelist=check_in_whitelist(input_file,white_list);
	if(in_whitelist)
	{
		printk("\n%s FILE IS GOOD FOUND IN WHITELIST.", filename);		
		goto out;
	}
	/* Check for virus content */
	is_virus=check_in_blacklist(input_file,black_list);
	if(is_virus)
	{
		printk("\nVIRUS FOUND IN FILE %s", filename);
		virus_file_name = kzalloc(PAGE_SIZE,GFP_KERNEL);
		strcpy(virus_file_name,filename);
		strcat(virus_file_name,".virus");
		virus_file_name[strlen(virus_file_name)]='\0';
		printk("\n %s", virus_file_name);
		
		virus_file = filp_open(virus_file_name, O_CREAT, 0);
        	if(IS_ERR(virus_file)) {
			err = PTR_ERR(virus_file);
                	printk("\nError in black list file open");
			goto out;
   		}

		//rename the file.
		rename_file(input_file,virus_file);			
		goto out;
	}
	else
	{
		printk("\n%s File is good",filename);
	}
out:	
	/*Close blacklist file */
	if(black_list)
		filp_close(black_list, NULL);

	/*Close whitelist file */
	if(white_list)
		filp_close(white_list,NULL);

	/*Close input file */
	if(input_file)
		filp_close(input_file,NULL);

	/*Free memory*/	
	if(virus_file_name)
		kfree(virus_file_name);		
	return err;
}


