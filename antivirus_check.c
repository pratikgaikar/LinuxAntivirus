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
#include <error.h>
extern int process(const char *file, const struct stat *sb,
		   int flag, struct FTW *s);
int total_files=0;
int virus_files=0;

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
		printf("FilePath=%s\n",filePath);
		//iterate over a particular directory provided
		if (nftw(argv[i], process, nfds, flags) != 0) {
			fprintf(stderr, "%s: %s: Not a valid filename/directory\n",
				argv[0], argv[i]);
			}
		if(filePath!=NULL)		
			free(filePath);
	}
	printf("Total Files Scanned=%d\n",total_files);
	if(virus_files!=0)
		printf("Virus found in %d files\n",virus_files);
	else
		printf("No virus files found\n");
	if ((flags & FTW_CHDIR) != 0) {
		getcwd(finish, sizeof finish);
		printf("Starting dir: %s\n", start);
		printf("Finishing dir: %s\n", finish);
	}

	return 0;
}

/*
  processing the files according to the types.
*/
int process(const char *file, const struct stat *sb,
	    int flag, struct FTW *s)
{
	int retval = 0,rc=0;
	char *buf=NULL;
	char command[4200], msg1[4200];
	switch (flag) {
	case FTW_SL:
		buf=malloc(4096);		
		realpath(file, buf);
		file=buf;	
	case FTW_F:
		printf("scanning file %s\n", file);
		total_files+=1;		
		if(strstr(file, ".virus")!=NULL) {
			virus_files+=1;	
			//printf("File %s is a virus file\n", file);
			strcpy(command,"notify-send -i error ");
                	strcpy(msg1,"\" VIRUS file found: \"");
                	strcat(msg1,file);
			strcat(msg1,"\" cannot open \"");
                	strcat(command,msg1);
                	system(command);
			
		} else {
			retval= open(file,O_RDONLY);
			//printf("Return value: %d \t errno : %d\n", retval,errno);
			if(retval>-1)
			{	
				printf("No virus found\n");
				close(retval);
			}
			else if(retval==-1&& errno==9)
			{	
				virus_files+=1;
				printf("Virus found\n");
				
			}
			retval=0;

		}
		if(buf!=NULL)
		  free(buf);
		break;
	case FTW_D:		
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
	default:
		//printf("%s: unknown flag %d: can't happen!\n", name, flag);
		retval = 1;
		break;
	}
	
	return retval;
}
