#define _XOPEN_SOURCE 1			
#define _XOPEN_SOURCE_EXTENDED 1	

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <ftw.h>	
#include <limits.h>     
#include <unistd.h>	
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

extern int process(const char *file, const struct stat *sb,
		   int flag, struct FTW *s);

int main(int argc, char **argv)
{
	int i, c, nfds;
	int flags = FTW_PHYS;
	char start[PATH_MAX], finish[PATH_MAX];
	if (optind == argc)
	 {
		printf("Usage:Pass a directory or filename to be scanned\n");
	 }
	getcwd(start, sizeof start);
	nfds = getdtablesize() -5;
	for (i = optind; i < argc; i++) {
		char * filePath=malloc(4096);
		filePath[0]='\0';
		if(*argv[1]!='/')
		{
		   strcat(filePath,start);
		   strcat(filePath,"/");
		   strcat(filePath,argv[i]); 	 
		}
		else
		{
		   strcat(filePath,argv[i]);
		}
		//printf("FilePath=%s\n",filePath);
		if (nftw(filePath, process, nfds, flags) != 0) {
			fprintf(stderr, "%s: %s: Not a valid filename/directory\n",
				argv[0], argv[i]);
			}
		free(filePath);
	}

	if ((flags & FTW_CHDIR) != 0) {
		getcwd(finish, sizeof finish);
		printf("Starting dir: %s\n", start);
		printf("Finishing dir: %s\n", finish);
	}

	return 0;
}


int process(const char *file, const struct stat *sb,
	    int flag, struct FTW *s)
{
	int retval = 0;
	
	switch (flag) {
	case FTW_SL:
		//printf("%s (symlink)\n", file);			
		char buf[PATH_MAX + 1];
		realpath(file, buf);
		//printf("%s (realpath)\n", buf);			
		file=buf;
	case FTW_F:
		printf("%s (file)\n", file);
		if(strstr(file, ".virus")!=NULL) {	
			//printf("File %s is a virus file\n", file);		
			errno=9;
		} else {
			retval = open(file,O_RDONLY);
			printf("Return value: %d \t errno : %d\n", retval,errno);
		}
		break;
	/*case FTW_D:		
		//printf("%s (directory)\n", name);
		break;
	case FTW_DNR:
		//printf("%s (unreadable directory)\n", name);
		break;
	case FTW_NS:
		//printf("%s (stat failed): %s\n", name, strerror(errno));
		break;
	case FTW_DP:
		break;
	case FTW_SLN:
		//printf("%s: FTW_DP or FTW_SLN: can't happen!\n", name);
		retval = 1;
		break;
	*/
	default:
		//printf("%s: unknown flag %d: can't happen!\n", name, flag);
		retval = 1;
		break;
	}
	if(errno==9)
	{
		//Notify
		char *name="File.txt";
		char command[100], msg[100];
		
		strcpy(command,"notify-send ");
		strcpy(msg,"\"VIRUS FOUND: \"");
		strcat(msg,name);
		strcat(command,msg);
//system("/usr/bin/notify-send MessageSubject: \"Virus file :\"%s", name);
//system("/usr/bin/notify-send MessageSubject 'tail $name' -t 5000");
//system("/usr/bin/notify-send Cron message $i" done);
//system("/usr/bin/notify-send Test "<font size=16 color=blue><b><i>Hello World</b></i></font>);
//system("/usr/bin/xmessage");
system(command);
	}
	return retval;
}

