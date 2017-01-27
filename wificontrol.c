/*
 * wificontrol -- wifi control utility for Inteno routers
 *
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: sukru.senli@inteno.se
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tools.h"

#define PORT 9876
#define BUF_SIZE 2000
#define CLADDR_LEN 100

extern bool arping(const char *targetIP, char *device, int toms);

static int client_connected = 0;
static pthread_t tid;
pthread_mutex_t lock;

static int arp_ping(const char *ipaddr, char *device, int tmo, int retry)
{
	int ret = 0;
	int i;

	for(i = 0; i < retry; i++) {
		usleep(100000);
		if (client_connected == 1)
			continue;
		if(arping(ipaddr, device, tmo)) {
			ret = 1;
			break;
		}
	}

	if (ret) {
		system("ubus -t 1 call led.internet set '{\"enable\":0}'");
	} else {
		system("ubus -t 1 call led.internet set '{\"enable\":1}'");
		system("ubus -t 1 call led.internet set '{\"state\":\"error\"}'");
	}

	return ret;
}

void *ping_uplink(void *arg)
{
	const char *ipaddr;
	unsigned long sleep = 5;
	char output[64];

	while (1) {
		usleep(sleep*1000000);
		if (client_connected == 1)
			continue;
		ipaddr = chrCmd(output, 64, "ip r | grep default | awk '{print$3}'");
		if(strlen(ipaddr) < 7)
			continue;
		if(arp_ping(ipaddr, "br-wan", 2000, 5) == 0 && client_connected == 0) {
			sleep = 10;
		} else {
			sleep = 5;
		}
	}

	return NULL;
}

int wifiserver(void) {
	socklen_t len;
	struct sockaddr_in addr, cl_addr;
	int sockfd, ret, newsockfd;
	char buffer[BUF_SIZE];
	char output[BUF_SIZE];
	pid_t childpid;
	char clientAddr[CLADDR_LEN];
	int status;
	int pt;

	if ((pt = pthread_create(&tid, NULL, &ping_uplink, NULL) != 0)) {
		fprintf(stderr, "Failed to create thread\n");
		return 1;
	}
 
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
		client_connected = 0;
		len = sizeof(cl_addr);
		newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &len);
		if (newsockfd < 0) {
			printf("Error accepting connection!\n");
			return -1;
		}

		client_connected = 1;
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
		
				if (strncmp(buffer, "wifi import", 11) && strncmp(buffer, "wlctl", 5))
					strcpy(buffer, "echo Invalid call to wificontrol");

				ret = sendto(newsockfd, chrCmd(output, BUF_SIZE, buffer), BUF_SIZE, 0, (struct sockaddr *) &cl_addr, len);
				if (ret < 0) {
					//printf("Error sending data!\n");
					exit(1);
				}  
				//printf("Sent data to %s: %s\n", clientAddr, chrCmd(output, BUF_SIZE, buffer));
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

	pthread_mutex_lock(&lock);

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
		ret = connect(sockfd, (struct sockaddr *) &addr, (socklen_t)sizeof(addr));
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

	pthread_mutex_unlock(&lock);

	return 0;
}

int get_assoclist(char *serverAddr) {
	struct sockaddr_in addr;
	int sockfd, ret;
	char buffer[BUF_SIZE];
	fd_set fdset;
	struct timeval tv;

	pthread_mutex_lock(&lock);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return -1;
	}

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
			return -1;
		}

		sprintf(buffer, "wlctl -i wl0 assoclist | awk '{print$2}' | tr '\n' ' '; wlctl -i wl1.1 assoclist | awk '{print$2}' | tr '\n' ' '");

		ret = sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			return -1;
		}
		ret = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
		if (ret >= 0) {
			if (strstr(buffer, ":"))
				fputs(buffer, stdout);
		}
	}

 	close(sockfd);

	pthread_mutex_unlock(&lock);

	return 0;
}  

int wificlient(void) {
	FILE *leases, *arpt;
	char line[256];
	char leaseno[256];
	char macaddr[256];
	char ipaddr[256];
	char hostname[256];
	char mask[256];
	char device[256];
	char ssid[256];
	char key[256];
	char ripaddr[1000];
	int hw, flag;
	char output[256];

	strncpy(ssid, chrCmd(output, 256, "uci -q get wireless.@wifi-iface[0].ssid"), 256);
	strncpy(key, chrCmd(output, 256, "uci -q get wireless.@wifi-iface[0].key"), 256);

	if ((leases = fopen("/var/dhcp.leases", "r"))) {
		while(fgets(line, sizeof(line), leases) != NULL)
		{
			remove_newline(line);
			if (sscanf(line, "%s %s %s %s %s", leaseno, macaddr, ipaddr, hostname, mask) == 5) {
				if(is_inteno_macaddr(macaddr)) {
					connectAndRunCmd(ipaddr, ssid, key);
					strcat(ripaddr, ipaddr);
					strcat(ripaddr, " ");
				}
			}
		}
		fclose(leases);
	}

	memset(macaddr, '\0', sizeof(macaddr));
	memset(ipaddr, '\0', sizeof(ipaddr));

	if ((arpt = fopen("/proc/net/arp", "r"))) {
		while(fgets(line, sizeof(line), arpt) != NULL)
		{
			remove_newline(line);
			if (sscanf(line, "%s 0x%d 0x%d %s %s %s", ipaddr, &hw, &flag, macaddr, mask, device) == 6) {
				if(is_inteno_macaddr(macaddr)) {
					connectAndRunCmd(ipaddr, ssid, key);
				}
			}
		}
		fclose(arpt);
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
	int assoclist = 0;
	int client_mode = 0;
	int server_mode = 0;
	int opt;

	if (argc < 2)
		usage();

	while ((opt = getopt(argc, argv, "acs")) != -1) {

		switch (opt) {
			case 'a':
				assoclist = 1;
				break;
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

	if(assoclist)
		get_assoclist(argv[0]);
	else if(client_mode)
		wificlient();
	else if(server_mode)
		wifiserver();
	else if(argv[1] && argv[2])
		connectAndRunCmd(argv[0], argv[1], argv[2]);
	else
		usage();

	return 0;	
}
