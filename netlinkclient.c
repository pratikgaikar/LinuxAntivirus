#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

#define MYPROTO NETLINK_USERSOCK
#define MYMGRP 21
#define MAX_PAYLOAD 1024

int open_netlink(void)
{
    	int sock;
    	struct sockaddr_nl addr;
	int group = MYMGRP;
	sock = socket(AF_NETLINK, SOCK_RAW, MYPROTO);
    	if (sock < 0) {
        	printf("Error in sock creation.\n");
        	return sock;
    	}
	memset((void *) &addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
    	addr.nl_pid = getpid();
       	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("error in binding socet.\n");
        return -1;
    	}
	
	if (setsockopt(sock, 270, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        	printf("setsockopt < 0\n");
        	return -1;
    	}
    	
	return sock;
}

int read_event(int sock)
{    
	struct sockaddr_nl nladdr;
    	struct msghdr msg;
 	struct iovec iov;
    	char buffer[65536];
	char command[4200], msg1[4200];
    	int ret;
    	iov.iov_base = (void *) buffer;
    	iov.iov_len = sizeof(buffer);
    	msg.msg_name = (void *) &(nladdr);
    	msg.msg_namelen = sizeof(nladdr);
    	msg.msg_iov = &iov;
    	msg.msg_iovlen = 1;
    	printf("Listening.\n");
    	ret = recvmsg(sock, &msg, 0);
    	if (ret < 0)
        	printf("ret < 0.\n");
    	else
	{
        	printf("Received message: %s\n", NLMSG_DATA((struct nlmsghdr *) &buffer));
		strcpy(command,"notify-send ");
                strcpy(msg1,"\"VIRUS FOUND: \"");
                strcat(msg1,NLMSG_DATA((struct nlmsghdr *) &buffer));
                strcat(command,msg1);
                system(command);
		if(strcmp(NLMSG_DATA((struct nlmsghdr *) &buffer),"EXIT")==0)
		{
			printf("Should exit");
			exit(0);
		}	
	}
}


int main(int argc, char *argv[])
{
    	int nls;
    	nls = open_netlink();
       	if (nls < 0)
        	return nls;
	while (1)
    	{
		read_event(nls);
    	}
    	return 0;
}
