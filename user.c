#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

#define PROTOCOL NETLINK_USERSOCK
#define GRP 21
#define MAX_PAYLOAD 1024

int open_netlink(void)
{
    	int sock, group, ret;
    	struct sockaddr_nl address;
	group = GRP;

	sock = socket(AF_NETLINK, SOCK_RAW, PROTOCOL);
    	if (sock < 0) {
        	printf("Error in sock creation.\n");
        	return sock;
    	}

	/*Clear memory of structure address */
	memset((void *) &address, 0, sizeof(address));
	/*SET FAMILY AS NETLINK FAMILY*/	
	address.nl_family = AF_NETLINK;
	/*GET CURRENT PROCESS PIS */
	address.nl_pid = getpid();
	/*bind socket to address */	
	ret = bind(sock, (struct sockaddr *) &address, sizeof(address));
       	if ( ret < 0 ) {
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
	struct sockaddr_nl address;
    	struct msghdr msg;
 	struct iovec iov;
    	char buffer[65536];
	char command[4200], msg1[4200];
    	int ret;
    	iov.iov_base = (void *) buffer;
    	iov.iov_len = sizeof(buffer);
    	msg.msg_name = (void *) &(address);
    	msg.msg_namelen = sizeof(address);
    	msg.msg_iov = &iov;
    	msg.msg_iovlen = 1;
       	ret = recvmsg(sock, &msg, 0);
    	if (ret < 0)
        	printf("ret < 0.\n");
    	else
	{
		/*Termination condition */
        	if(strcmp(NLMSG_DATA((struct nlmsghdr *) &buffer),"EXIT")==0)
		{
			strcpy(command,"notify-send -i face-angry.png ");
                	strcpy(msg1,"\"Antivirus uninstalled \"");
			strcat(command,msg1);
                	system(command);			
			exit(0);
		}
		else
		{
			strcpy(command,"notify-send ");
                	strcpy(msg1,"\"VIRUS FOUND  \"");
                	strcat(msg1,NLMSG_DATA((struct nlmsghdr *) &buffer));
			strcat(command,msg1);
                	system(command);
		}	
	}
}

int main(int argc, char *argv[])
{
    	int sock;
    	sock = open_netlink();
       	if (sock < 0)
        	return sock;
	while (1)
    	{
		read_event(sock);
    	}
    	return 0;
}
