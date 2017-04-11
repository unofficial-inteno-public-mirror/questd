#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "tools.h"

#define MAX_REPEATERS (255)
#define BUFFER_SIZE (1024)
#define WIFICONTROL_LISTENING_PORT (9875)
#define WIFICONTROL_DEFAULT_FILE "/tmp/wificontrol.txt"

char *filename;
char *destination;
int client_connected;


enum RUNNING_MODE {
	MODE_NONE,
	MODE_ROUTER,
	MODE_ROUTER_ASSOCLIST,
	MODE_REPEATER,
	MODE_COUNT
};
enum RUNNING_MODE mode = MODE_NONE;


struct option long_options[] = {
	/* {char *name;	int has_arg;		int *flag;	int val; }*/
	{"router",	no_argument,		(int *)&mode,	MODE_ROUTER},
	{"assoclist",	no_argument,		(int *)&mode,	MODE_ROUTER_ASSOCLIST},
	{"repeater",	no_argument,		(int *)&mode,	MODE_REPEATER},
	{"file",	required_argument,	0,		'f'},
	{"destination",	required_argument,	0,		'd'},
	{0,		0,			0,		0}
};

extern bool arping(const char *targetIP, char *device, int toms);
/* TODO add usage() and functions definitions */

/* parse_args */
/* parse command line arguments */
void parse_args(int argc, char **argv)
{
	int c, option_index = 0;

	while (1) {
		c = getopt_long(argc, argv, "f:d:a",
			long_options, &option_index);

		/* printf("c = %d %c\n", c, c); */

		if (c == -1)
			break;

		switch (c) {
		case 0: /* long_options */
			break;
		case 'f': /* -f --file file.txt*/
			filename = strdup(optarg ? optarg : "");
			/* printf("file: \"%s\"\n", */
			/* 	filename ? filename : "(NULL)"); */
			break;
		case 'd': /* -d --destination 192.168.1.123*/
			destination = strdup(optarg ? optarg : "");
			/* printf("destination: \"%s\"\n", */
			/* 	destination ? destination : "(NULL)"); */
			break;
		case 'a': /* -a --assoclist */
			mode = MODE_ROUTER_ASSOCLIST;
			break;
		default:
			break;
		}
	}
}


static int arp_ping(const char *ipaddr, char *device, int tmo, int retry)
{
	int ret = 0;
	int i;

	for (i = 0; i < retry; i++) {
		usleep(100000);
		if (client_connected == 1)
			continue;
		if (arping(ipaddr, device, tmo)) {
			ret = 1;
			break;
		}
	}

	if (ret) {
		system("ubus -t 1 call led.internet set '{\"state\":\"notice\"}'");
		system("echo -e { \\\"online\\\" : true } > /tmp/internet_connection_status");
	} else {
		system("ubus -t 1 call led.internet set '{\"state\":\"error\"}'");
		system("echo -e { \\\"online\\\" : false } > /tmp/internet_connection_status");
	}

	return ret;
}


static void sleeps(int seconds)
{
	usleep(seconds*1000000);
}

void *ping_uplink(void *arg)
{
	int rv;
	char ipaddr[64] = {0};
	char device[64] = {0};
	unsigned long sleep = 5;
#if IOPSYS_BROADCOM
	char assoclist[512];
#elif IOPSYS_MEDIATEK
	char wetif[64];
	int autoc = 1;
#endif

	pthread_detach(pthread_self());

	while (1) {
		sleeps(sleep);
		if (client_connected == 1)
			continue;
		memset(ipaddr, 0, 64);
		chrCmd(ipaddr, 64, "ip r | grep default | awk '{print$3}'");
		if (strlen(ipaddr) < 7)
			continue;
		memset(device, 0, 64);
		chrCmd(device, 64, "ip r | grep default | awk '{print$5}'");
		if (strlen(device) < 3)
			continue;
		rv = arp_ping(ipaddr, device, 2000, 5);
		if (rv == 0 && client_connected == 0) {
#if IOPSYS_BROADCOM
			memset(assoclist, 0, 512);
			chrCmd(assoclist, 512,
			"wlctl -i wl1 assoclist | head -1 | awk '{print$2}'");
			runCmd("wlctl -i wl1 reassoc %s", assoclist);
			/* runCmd("killall -9 udhcpc &"); */
#elif IOPSYS_MEDIATEK
			/* Disconnect clients on 2.4GHz radio */
			runCmd("iwpriv ra0 set DisConnectAllSta=2");
			/* Disconnect clients on 5GHz radio */
			runCmd("iwpriv rai0 set DisConnectAllSta=2");
			memset(wetif, 0, 64);
			chrCmd(wetif, 64, "uci -q get wireless.$(uci show wireless | grep 'mode=.*wet.*' | cut -d'.' -f2).ifname");
			if (autoc) {
				runCmd("iwpriv %s set ApCliAutoConnect=1",
					wetif);
				autoc = 0;
			} else {
				runCmd("iwpriv %s set ApCliEnable=0", wetif);
				runCmd("iwpriv %s set ApCliEnable=1", wetif);
				autoc = 1;
				sleeps(60);
			}
#endif
			sleep = 10;
		} else {
			sleep = 5;
		}
	}

	return NULL;
}


/* collect_intenos_on_network */
/* populates the repeaters array with the host on the lan */
/* that have inteno mac and are possibly repeaters */
int collect_intenos_on_network(char **repeaters, int i, const char *network)
{
	int rv;
	char line[256];
	char network_ip[17], netmask[17];
	char ip[17], mac[18];
	FILE *arp;

	/* get network ip */
	chrCmd(network_ip, 17, "uci -q get network.%s.ipaddr", network);

	/* get netmask */
	chrCmd(netmask, 17, "uci -q get network.%s.netmask", network);
	/* printf("netmask \"%s\"\n", netmask); */

	/* parse the arp table in search of inteno repeaters on the lan */
	arp = fopen("/proc/net/arp", "r");
	if (!arp)
		return i;
	fgets(line, sizeof(line), arp); /* dump the first line */
	while (fgets(line, sizeof(line), arp)) {
		if (i >= MAX_REPEATERS)
			break;
		trim(line);
		/*printf("line: \"%s\"\n", line);*/
		/* IP address	HW type	Flags	HW address	Mask	Device
		* 192.168.1.140	0x1	0x2	02:0c:07:07:74:b8  *	br-lan
		*/
		rv = sscanf(line, "%16s %*s %*s %17s %*s %*s", ip, mac);
		/* printf("line: rv = %d ip \"%s\" mac \"%s\"\n", rv, ip, mac); */
		if (rv != 2)
			continue;
		if (!is_inteno_macaddr(mac))
			continue;
		if (!is_ip_in_network(ip, network_ip, netmask))
			continue;
		/* printf("ip \"%s\" is inteno product and in lan network\n", ip); */

		/* add repeater's ip in the array */
		repeaters[i++] = strdup(ip);
	}
	fclose(arp);
	return i;
}

/* this function allocates memory. free it! when no longer needed */
char **collect_repeaters(void)
{
	int i;
	char **repeaters = NULL;
	struct uci_context *uci_ctx = NULL;
	struct uci_package *uci_pkg;
	struct uci_element *e;
	struct uci_section *s;
	char *is_lan = NULL;
	char *name = NULL;

	repeaters = (char **)malloc(MAX_REPEATERS * sizeof(char *));
	if (!repeaters)
		goto out;

	for (i = 0; i < MAX_REPEATERS; i++)
		repeaters[i] = NULL;

	uci_pkg = init_package(&uci_ctx, "network");

	if (!uci_pkg)
		goto out;

	i = 0;
	uci_foreach_element(&uci_pkg->sections, e) {
		name = strdup(e->name);
		if (!name)
			goto next;

		s = uci_to_section(e);
		if (strcmp(s->type, "interface") != 0)
			goto next;

		if (strcmp(name, "loopback") == 0)
			goto next;

		is_lan = uci_lookup_option_string(uci_ctx, s, "is_lan");
		if(!is_lan)
			goto next;

		if (strncmp(is_lan, "1", 1) == 0){
			i = collect_intenos_on_network(repeaters, i, name);
		}
next:
		if (name)
			free(name);
		name = NULL;
	}
	free_uci_context(&uci_ctx);
out:
	return repeaters;
}

/* fopen_wrapper */
/* opens filename if this is present */
/* else it opens the default file */
FILE *fopen_wrapper(char *filename, char *mode)
{
	FILE *file = NULL;

	if (filename)
		file = fopen(filename, mode);

	if (!file)
		file = fopen(WIFICONTROL_DEFAULT_FILE, mode);

	return file;
}

int prepare_socket(char *ip)
{
	int sock, rv;
	struct sockaddr_in addr;
	struct timeval tv;

	/* create a socket */
	sock = socket(AF_INET, SOCK_STREAM, 0 /* IP */);
	if (sock == -1) {
		perror("socket");
		return 0;
	}

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	rv = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (rv == -1) {
		perror ("setsockopt SO_RCVTIMEO");
		goto error;
	}
	rv = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (rv == -1) {
		perror ("setsockopt SO_SNDTIMEO");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(WIFICONTROL_LISTENING_PORT);

	/* connect etc */
	rv = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (rv == -1) {
		perror("connect");
		goto error;
	}
	return sock;
error:
	close(sock);
	return 0;
}

/* send_data */
/* send data to a repeater identified by ip */
void send_data(char *ip)
{
	int sock, rv;
	FILE *file;
	char buffer[BUFFER_SIZE];

	sock = prepare_socket(ip);
	if (!sock) {
		perror("socket");
		return;
	}

	/* open file for reading */
	file = fopen_wrapper(filename, "r");
	if (!file) {
		perror("fopen_wrapper");
		goto out;
	}

	/* read data from file and send it to the repeater */
	while (1) {
		memset(buffer, 0, BUFFER_SIZE);
		rv = fread(buffer, sizeof(char), BUFFER_SIZE, file);
		if (rv <= 0)
			break;
		rv = send(sock, buffer, rv, 0);
		if (rv == -1) {
			perror("send");
			break;
		}
	}
	if (ferror(file))
		perror("fgets");

	if (file && file != stdin)
		fclose(file);
out:
	close(sock);
}


/* retrieve assoclist from repeater */
void retrieve_assoclist(char *ip)
{
	int sock, rv, nbytes;
	char buffer[BUFFER_SIZE];

	sock = prepare_socket(ip);
	if (!sock) {
		perror("socket");
		return;
	}

	memset(buffer, 0, BUFFER_SIZE);
	snprintf(buffer, BUFFER_SIZE, "give_me_assoclist");
	/* printf("buffer: \"%s\"\n", buffer); */
	rv = send(sock, buffer, strlen(buffer), 0);
	if (rv == -1) {
		perror("send");
		goto out;
	}

	/* printf("sent buffer: \"%s\" rv = %d\n", buffer, rv); */
	/* receive data */
	while (1) {
		memset(buffer, 0, BUFFER_SIZE);
		rv = recv(sock, buffer, BUFFER_SIZE, 0);
		/* printf("recv buffer \"%s\" %d\n", buffer, rv); */
		if (rv < 0) {
			perror("recv");
			break;
		}
		if (rv == 0)
			break;

		/* printf ("recv buffer: \"%s\"\n", buffer); */
		nbytes = fwrite(buffer, sizeof(char), rv, stdout);
		if (nbytes != rv) {
			perror("fwrite");
			break;
		}
	}
out:
	close(sock);
}


/* router_mode */
/* main function when running in --router mode */
void router_mode(void)
{
	int i;
	char **repeaters = NULL;

	/* printf("Router mode\n"); */
	repeaters = collect_repeaters();

	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		/* printf("repeater[%d]: \"%s\"\n", i, repeaters[i]); */

	/* send data to each (possible) repeater found on lan */
	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		send_data(repeaters[i]);

	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		free(repeaters[i]);
}


/* repeater_mode */
/* main function when running in --repeater mode */
void repeater_mode(void)
{
	int sock, connection, rv, nbytes, yes = 1;
	char buffer[BUFFER_SIZE], md5_before[64], md5_after[64];
	struct sockaddr_in addr, remote_addr;
	socklen_t remote_addr_len;
	FILE *file = NULL;
	pthread_t ping_thread;

	/* printf("Repeater mode\n"); */

	/* create a thread that trigger wireless reassociation if needed */
	rv = pthread_create(&ping_thread, NULL, &ping_uplink, NULL);
	if (rv != 0) {
		perror("pthread_create");
		return;
	}

	/* create a socket */
	sock = socket(AF_INET, SOCK_STREAM, 0 /* IP */);
	if (sock == -1) {
		perror("socket");
		return;
	}

	/* set socket option SO_REUSEADDR */
	rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (rv == -1) {
		perror("setsockopt");
		close(sock);
		return;
	}

	/* prepare the address for bind */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(WIFICONTROL_LISTENING_PORT);

	/* bind the address to the socket */
	rv = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (rv == -1) {
		perror("bind");
		close(sock);
		return;
	}

	/* listen on connections */
	rv = listen(sock, 5 /* MAXPENDING */);
	if (rv == -1) {
		perror("listen");
		close(sock);
		return;
	}

	while (1) {
		client_connected = 0;

		/* accept a connection on the listening socket */
		remote_addr_len = sizeof(remote_addr);
		connection = accept(sock,
			(struct sockaddr *) &remote_addr, &remote_addr_len);

		if (connection == -1) {
			perror("accept");
			continue;
		}

		if (remote_addr_len != sizeof(remote_addr)) {
			close(connection);
			continue;
		}
		client_connected = 1;
		/* printf("a connection from %s\n", inet_ntoa(remote_addr.sin_addr)); */

		/* TODO check that remote_addr is the gateway and is inteno */

		/* receive data */
		while (1) {
			memset(buffer, 0, BUFFER_SIZE);
			/* printf("before recv\n"); */
			rv = recv(connection, buffer, BUFFER_SIZE, 0);
			/* printf("after recv rv = %d\n", rv); */
			if (rv < 0) {
				perror("recv");
				break;
			}
			if (rv == 0)
				break;

			if (strstr(buffer, "give_me_assoclist")) {
				/* printf("give_me_assoclist\n"); */
				memset(buffer, 0, BUFFER_SIZE);
				chrCmd(buffer, BUFFER_SIZE - 1,
				"ubus -t 1 call router.wireless assoclist | grep macaddr | cut -d'\"' -f4 | sort -u | tr '\n' ' '");

				/* printf("buffer: \"%s\"\n", buffer); */
				rv = send(connection, buffer, strlen(buffer), 0);
				if (rv == -1) {
					perror("send");
					break;
				}
				break;
			}
			/* printf("NOT give_me_assoclist\n"); */

			/* open file for writing */
			if (!file) {
				memset(md5_before, 0, 64);
				chrCmd(md5_before, 64, "md5sum %s 2>/dev/null | awk '{print $1}'",
					filename ? filename : WIFICONTROL_DEFAULT_FILE);
				file = fopen_wrapper(filename, "w");
				if (!file) {
					perror("fopen_wrapper");
					close(connection);
					break;
				}
			}

			nbytes = fwrite(buffer, sizeof(char), rv, file);
			if (nbytes != rv) {
				perror("fwrite");
				break;
			}
		}

		if (file) {
			fclose(file);
			file = NULL;

			memset(md5_after, 0, 64);
			chrCmd(md5_after, 64, "md5sum %s 2>/dev/null | awk '{print $1}'",
				filename ? filename : WIFICONTROL_DEFAULT_FILE);
			if (strncmp(md5_before, md5_after, 64) != 0) {
				/* apply the new wireless settings */
				/* printf("Applying new wireless settings\n"); */
				runCmd(
				"ubus call repeater set_creds '{\"file\":\"%s\"}'",
				filename ? filename : WIFICONTROL_DEFAULT_FILE);
			}
		}
		close(connection);

	}

}

int main(int argc, char **argv)
{

	parse_args(argc, argv);

	/* printf("mode = %d\n", mode); */

	if (mode == MODE_NONE)
		return 1;

	if (mode == MODE_ROUTER)
		router_mode();
	if (mode == MODE_ROUTER_ASSOCLIST)
		retrieve_assoclist(destination);

	if (mode == MODE_REPEATER)
		repeater_mode();

	if (filename)
		free(filename);
	if (destination)
		free(destination);

	return 0;
}
