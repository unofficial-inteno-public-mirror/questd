 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#define PORT 9876
#define BUF_SIZE 2000
#define CLADDR_LEN 100

static void 
removeNewline(char *buf)
{
	int len;
	len = strlen(buf) - 1;
	if (buf[len] == '\n') 
		buf[len] = 0;
}

static const char*
chrCmd(char *cmd)
{
	FILE *pipe = 0;
	static char buffer[BUF_SIZE] = {0};
	if ((pipe = popen(cmd, "r"))){
		fgets(buffer, sizeof(buffer), pipe);
		pclose(pipe);

		removeNewline(buffer);
		if (strlen(buffer))
			return (const char*)buffer;
		else
			return "";
	} else {
		return "";
	}
}

int wifiserver(void) {
	struct sockaddr_in addr, cl_addr;
	int sockfd, len, ret, newsockfd;
	char buffer[BUF_SIZE];
	pid_t childpid;
	char clientAddr[CLADDR_LEN];
	int status;
 
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("Error creating socket!\n");
		return -1;
	}
	//printf("Socket created...\n");
 
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(PORT);
 
	ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		printf("Error binding!\n");
		close(sockfd);
		return -1;
	}
	//printf("Binding done...\n");

	//printf("Waiting for a connection...\n");
	listen(sockfd, 5);

	for (;;) {
		len = sizeof(cl_addr);
		newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &len);
		if (newsockfd < 0) {
			printf("Error accepting connection!\n");
			return -1;
		}
		//printf("Connection accepted...\n");

		inet_ntop(AF_INET, &(cl_addr.sin_addr), clientAddr, CLADDR_LEN);
		if ((childpid = fork()) == 0) {
			close(sockfd);
			for (;;) {
		    		memset(buffer, 0, BUF_SIZE);
		   		ret = recvfrom(newsockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &cl_addr, &len);
				if(ret < 0) {
					printf("Error receiving data!\n");
					exit(1);
				}
				//printf("Received data from %s: %s\n", clientAddr, buffer);
		
				if (strncmp(buffer, "wifi import", 11))
					strcpy(buffer, "echo Invalid call to wificontrol");

				ret = sendto(newsockfd, chrCmd(buffer), BUF_SIZE, 0, (struct sockaddr *) &cl_addr, len);
				if (ret < 0) {
					//printf("Error sending data!\n");
					exit(1);
				}  
				//printf("Sent data to %s: %s\n", clientAddr, chrCmd(buffer));
			}
		} else if (childpid > 0) {
			waitpid(childpid, &status, 0);
		}

		close(newsockfd);
 	}
	return 0;
}

int connectAndRunCmd(char *serverAddr, char *ssid, char *key) {
	struct sockaddr_in addr;
	int sockfd, ret;
	char buffer[BUF_SIZE];
	fd_set fdset;
	struct timeval tv;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("Error creating socket!\n");
		return -1;
	}  
	//printf("Socket created...\n");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(serverAddr);
	addr.sin_port = htons(PORT);

	FD_ZERO(&fdset);
	FD_SET(sockfd, &fdset);
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	if (select(sockfd+1, &fdset, NULL, NULL, &tv) > 0) {
		ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			close(sockfd);
			printf("Error connecting to the server %s\n", serverAddr);
			return -1;
		}
		//printf("Connected to %s\n", serverAddr);

		sprintf(buffer, "wifi import '{\"ssid\":\"%s\",\"key\":\"%s\"}' &", ssid, key);
		ret = sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			printf("Error sending data!\n\t-%s", buffer);
		}
		ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
		if (ret < 0) {
			printf("Error receiving data!\n");
		} /*else {
			printf("Received: ");
			fputs(buffer, stdout);
			printf("\n");
		}*/
	}

 	close(sockfd);

	return 0;
}  

int wificlient(void) {
	FILE *leases;
	char line[256];
	char leaseno[256];
	char macaddr[256];
	char ipaddr[256];
	char hostname[256];
	char mask[256];
	char ssid[256];
	char key[256];

	strcpy(ssid, chrCmd("uci -q get wireless.@wifi-iface[-1].ssid"));
	strcpy(key, chrCmd("uci -q get wireless.@wifi-iface[-1].key"));

	if ((leases = fopen("/var/dhcp.leases", "r"))) {
		while(fgets(line, sizeof(line), leases) != NULL)
		{
			removeNewline(line);
			if (sscanf(line, "%s %s %s %s %s", leaseno, macaddr, ipaddr, hostname, mask) == 5) {
				if(strstr(macaddr, "00:22:07"))
					connectAndRunCmd(ipaddr, ssid, key);
			}
		}
		fclose(leases);
	}

	return 0;
}

void usage(void){
	printf("wificontrol -s\n");
	printf("\trun in server mode and wait for client to push configuration\n\n");
	printf("wificontrol -c\n");
	printf("\tpush configuration to connected repeaters\n\n");
	printf("wificontrol <IPADDR> <SSID> <KEY>\n");
	printf("\tconfigure a specific device with specific SSID and Key\n");
	exit(1);
}

int main(int argc, char**argv) {
	int client_mode = 0;
	int server_mode = 0;
	int opt;

	if (argc < 2)
		usage();

	while ((opt = getopt(argc, argv, "cs")) != -1) {

		switch (opt) {
			case 'c':
				client_mode = 1;
				break;
			case 's':
				server_mode = 1;
				break;
			default:
				usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(client_mode)
		wificlient();
	else if(server_mode)
		wifiserver();
	else if(argv[1] && argv[2])
		connectAndRunCmd(argv[0], argv[1], argv[2]);
	else
		usage();

	return 0;	
}
