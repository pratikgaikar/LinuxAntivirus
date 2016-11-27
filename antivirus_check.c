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

int total_files=0;
int virus_files=0;

/*
  processing the files according to the types.
*/
int process_files(const char *file, const struct stat *stat_buf,int flag, struct FTW *ftw)
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
		printf("\t\tScanning file %s\n", file);
		total_files+=1;		
		if(strstr(file, ".virus")!=NULL) {
			virus_files+=1;	
			printf("\t\tResult:Virus File\n\n");
			strcpy(command,"notify-send -i error ");
                	strcpy(msg1,"\" VIRUS file found: \"");
                	strcat(msg1,file);
			strcat(msg1,"\" cannot open \"");
                	strcat(command,msg1);
                	system(command);
			
		} else {
			retval= open(file,O_RDONLY);
			if(retval>-1)
			{	
				printf("\t\tResult:Clean File\n\n");
				close(retval);
			}
			else if(retval==-1&& errno==9)
			{	
				virus_files+=1;
				printf("\t\tResult:Virus found\n\n");
				
			}
			retval=0;

		}
		if(buf!=NULL)
		  free(buf);
		break;
	case FTW_SLN:
		printf("\t\tSymbolic link %s pointing to a nonexistent file\n",file);
		break;	
	case FTW_DNR:
		printf("\t\tUnreadable Directory: %s\n",file);
		break;
	case FTW_NS:
		printf("\t\tStat failed to path: %s\n",file);
		break;
	case FTW_D :		
	case FTW_DP:
		break;
	default:
		retval = 1;
		break;
	}
	
	return retval;
}

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
		//iterate over a particular directory provided
		printf("------------------------------------------------------------------\n");
		printf("			SCANNING Started  			  \n");
		printf("------------------------------------------------------------------\n");
		if (nftw(argv[i], process_files, nfds, flags) != 0) {
			//Invalid directory/filename		
				fprintf(stderr, "%s: %s: \t\t Not a valid filename/directory\n",argv[0], argv[i]);
			}
		if(filePath!=NULL)		
			free(filePath);
	}
	printf("------------------------------------------------------------------\n");
	printf("			SCAN SUMMARY  				   \n ");
	printf("------------------------------------------------------------------\n");
	printf("\t\tTotal Files Scanned=%d\n",total_files);
	if(virus_files!=0)
		printf("\t\tVirus found in %d files\n",virus_files);
	else
		printf("\t\tNo virus files found\n");
	if ((flags & FTW_CHDIR) != 0) {
		getcwd(finish, sizeof finish);
		printf("Starting dir: %s\n", start);
		printf("Finishing dir: %s\n", finish);
	}

	return 0;
}


