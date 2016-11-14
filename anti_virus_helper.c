#include"antivirus.h"

int check_for_virus(char *filename)
{
	int err = 0;
	struct file *black_list= NULL, *input_file = NULL, *white_list = NULL;
	bool in_whitelist=false ,is_virus=false;

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
		goto out;
	}
	/* Check for virus content */
	/*is_virus=check_in_blacklist(input_file,black_list);
	if(is_virus)
	{
		//rename the file //or put it in the virus list.
		goto out;
	}*/
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
		
	return err;
}


