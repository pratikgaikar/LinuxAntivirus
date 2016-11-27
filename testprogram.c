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
	int f1 = open("testfiles/testfile1", O_RDONLY);
	if (f1 == -1)
	{
    		perror("Error opening file: ");
	}
	close(f1);

	int f2 = openat(AT_FDCWD, "testfiles/testfile2", O_RDONLY);
    	if(f2 == -1)
        {
    		perror("Error opening file: ");
	}
	close(f2);

    	char *arg[] = {"echo", "Hello", (char *) NULL};
    	if(fork() == 0) {
        	printf("Execv echo command\n");
        	error = execv("/bin/echo", arg);
		if(error = -1)        	
			perror("Error in execv: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}

	char *arg2[] = {"cat", "testfiles/testfile3", 0};
	if(fork() == 0) {
        	printf("Execvp cat command\n");
        	error = execvp("cat", arg2);
        	if(error = -1)        	
			printf("Error in execvp: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}

	if(fork() == 0) {
        	printf("Execl virus script command\n");
		error = execl("testfiles/testscript.sh", NULL, (char *)0);
		if(error = -1)        	
			printf("Error in execl: ");
		else
			printf("done\n\n"); 
    	} 
    	else {
        	sleep(2);
    	}
	
	if(fork() == 0) {
		printf("Execvpe antivirus scan command\n");		
		char *path = getenv("PATH");
    		char  pathenv[strlen(path) + sizeof("PATH=")];
    		char *envp[] = {pathenv, NULL};
    		char *tests[] = {"antivirus_scan", "testfiles/", NULL};
    		error = execvpe(tests[0], tests, envp);
		if(error = -1)        	
			printf("Error in execvpe: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	
	if(fork() == 0) {
		printf("Execlp pwd command\n");
		error = execlp("pwd", "pwd", "-P", (char *) NULL);
		if(error = -1)        	
			printf("Error in execlp: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}

	if(fork() == 0) {
		printf("Execle ls command\n");		
		char *env[] = { "HOME=/usr/home", "LOGNAME=home", (char *)0 };
		error = execle("/bin/ls", "ls", "-a", (char *)0, env);
		if(error = -1)        	
			printf("Error in execle: ");
		else
			printf("done\n\n");
    	} 
    	else {
        	sleep(2);
    	}
	
    	return 0;
}  
