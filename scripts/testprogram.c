//open, openat execl, execlp, execle, execv, execvp, execvpe system calls are tested

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	int error=0;

	/* Open system call is tested and if testfile1 contains virus, then it would not be opened*/	
	printf("------------------------------------------------------------------\n");
	printf("		Executing OPEN System Call  			  \n");
	printf("------------------------------------------------------------------\n");
	printf("File is opened using open system call\n");
	int f1 = open("../testfiles2/testfile1", O_RDONLY);
	if (f1 == -1)
	{
    		perror("Error opening file: ");
	}
	close(f1);
	printf("\n");


	/* Openat system call is tested and if testfile2 contains virus, then it would not be opened*/
	printf("------------------------------------------------------------------\n");
	printf("		Executing OPENAT System Call  			  \n");
	printf("------------------------------------------------------------------\n");	
	printf("File is opened using openat system call\n");	
	int f2 = openat(AT_FDCWD, "../testfiles2/testfile2", O_RDONLY);
    	if(f2 == -1)
        {
    		perror("Error opening file: ");
	}
	close(f2);
	printf("\n");

	/* Execv system call is tested*/
	printf("------------------------------------------------------------------\n");
	printf("		Executing EXECV System Call  			  \n");
	printf("------------------------------------------------------------------\n");	
    	char *arg[] = {"echo", "Hello", (char *) NULL};
    	if(fork() == 0) {
        	printf("Echo command is executed using execv system call\n");
        	error = execv("/bin/echo", arg);
		if(error = -1)        	
			perror("Error in execv: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	printf("\n");


	/* Execvp system call is tested and if testfile3 contains virus, then it would not be executed*/
	printf("------------------------------------------------------------------\n");
	printf("		Executing EXECVP System Call  			  \n");
	printf("------------------------------------------------------------------\n");
	char *arg2[] = {"cat", "../testfiles2/testfile3", 0};
	if(fork() == 0) {
        	printf("Cat command is executed using execvp system call\n");
        	error = execvp("cat", arg2);
        	if(error = -1)        	
			perror("Error in execvp: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	printf("\n");


	/* Execl system call is tested and if testscript.sh contains virus, then it would not be executed*/
	printf("------------------------------------------------------------------\n");
	printf("		Executing EXECL System Call  			  \n");
	printf("------------------------------------------------------------------\n");
	if(fork() == 0) {
        	printf("Testscript.sh is executed using execl system call\n");
		error = execl("../testfiles2/testscript.sh", NULL, (char *)0);
		if(error = -1)        	
			perror("Error in execl: ");
		else
			printf("done\n\n"); 
    	} 
    	else {
        	sleep(2);
    	}
	printf("\n");

	
	/* Execlp system call is tested */
	printf("------------------------------------------------------------------\n");
	printf("		Executing EXECLP System Call  			  \n");
	printf("------------------------------------------------------------------\n");
	if(fork() == 0) {
		printf("Pwd command is executed using execlp system call\n");
		error = execlp("pwd", "pwd", "-P", (char *) NULL);
		if(error = -1)        	
			perror("Error in execlp: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	printf("\n");


	/* Execle system call is tested */
	printf("------------------------------------------------------------------\n");
	printf("		Executing EXECLE System Call  			  \n");
	printf("------------------------------------------------------------------\n");
	if(fork() == 0) {
		printf("Ls command is executed using execle system call\n");		
		char *env[] = { "HOME=/usr/home", "LOGNAME=home", (char *)0 };
		error = execle("/bin/ls", "ls", "-a", (char *)0, env);
		if(error = -1)        	
			perror("Error in execle: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	printf("\n");


	/* Execvpe system call is tested to execute the antivirus_scan command*/
	printf("------------------------------------------------------------------\n");
	printf("		Executing EXECVPE System Call  			  \n");
	printf("------------------------------------------------------------------\n");
	if(fork() == 0) {
		printf("Antivirus scan is executed using execvpe system call\n");		
		char *path = getenv("PATH");
    		char  pathenv[strlen(path) + sizeof("PATH=")];
    		char *envp[] = {pathenv, NULL};
    		char *tests[] = {"antivirus_scan", "../testfiles2/", NULL};
    		error = execvpe(tests[0], tests, envp);
		if(error = -1)        	
			perror("Error in execvpe: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	printf("\n");

	
    	return 0;
}  
