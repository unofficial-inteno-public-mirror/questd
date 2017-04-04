#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "tools.h"

#define MAX_REPEATERS (255)
#define WIFICONTROL_LISTENING_PORT (9875)
#define WIFICONTROL_DEFAULT_FILE "/tmp/wificontrol.txt"

char *filename;
char *destination;


enum RUNNING_MODE {
	MODE_NONE,
	MODE_ROUTER,
	MODE_REPEATER,
	MODE_COUNT
};
enum RUNNING_MODE mode = MODE_NONE;

struct option long_options[] = {
	/* {char *name;	int has_arg;		int *flag;	int val; }*/
	{"router",	no_argument,		(int *)&mode,	MODE_ROUTER},
	{"repeater",	no_argument,		(int *)&mode,	MODE_REPEATER},
	{"file",	required_argument,	0,		'f'},
	{"destination",	required_argument,	0,		'd'},
	{0,		0,			0,		0}
};

void parse_args(int argc, char **argv)
{
	int c, option_index = 0;

	while (1) {
		c = getopt_long(argc, argv, "f:d:",
			long_options, &option_index);

		printf("c = %d %c\n", c, c);

		if (c == -1)
			break;

		switch (c) {
		case 0: /* long_options */
			break;
		case 'f': /* -f --file file.txt*/
			filename = strdup(optarg ? optarg : "");
			printf("file: \"%s\"\n",
				filename ? filename : "(NULL)");
			break;
		case 'd': /* -d --destination 192.168.1.123*/
			destination = strdup(optarg ? optarg : "");
			printf("destination: \"%s\"\n",
				destination ? destination : "(NULL)");
		default:
			break;
		}
	}

}

void collect_intenos_on_the_lan(char **repeaters)
{
	int len, rv, i;
	char line[256], *point1, *point2;
	char lanname[32], lanip[17], lanmask[17];
	char ip[17], mac[18];
	FILE *arp;

	/* get lanname */
	/* only the "first lan" is relevant for repeaters */
	chrCmd(line, 256,
	"uci -q show network | grep is_lan | grep -v loopback | head -n 1");
	point1 = strchr(line, '.');
	if (!point1)
		return;
	++point1;
	point2 = strchr(point1, '.');
	if (!point2)
		return;
	len = point2 - point1 < 32 ? point2 - point1 : 31;
	memcpy(lanname, point1, len);
	lanname[len] = '\0';
	printf("lanname \"%s\"\n", lanname);

	/* get lanip */
	chrCmd(lanip, 17, "uci -q get network.%s.ipaddr", lanname);
	printf("lanip \"%s\"\n", lanip);

	/* get lanmask */
	chrCmd(lanmask, 17, "uci -q get network.%s.netmask", lanname);
	printf("lanmask \"%s\"\n", lanmask);

	for (i = 0; i < MAX_REPEATERS && repeaters[i]; i++)
		;
	printf("repeaters index i = %d\n", i);

	/* parse the arp table in search of inteno repeaters on the lan */
	arp = fopen("/proc/net/arp", "r");
	if (!arp)
		return;
	fgets(line, sizeof(line), arp); /* dump the first line */
	while (fgets(line, sizeof(line), arp)) {
		trim(line);
		printf("line: \"%s\"\n", line);
		/* IP address	HW type	Flags	HW address	Mask	Device
		* 192.168.1.140	0x1	0x2	02:0c:07:07:74:b8  *	br-lan
		*/
		rv = sscanf(line, "%16s %*s %*s %17s %*s %*s", ip, mac);
		printf("line: rv = %d ip \"%s\" mac \"%s\"\n", rv, ip, mac);
		if (rv != 2)
			continue;
		if (!is_inteno_macaddr(mac))
			continue;
		if (!is_ip_in_network(ip, lanip, lanmask))
			continue;
		printf("ip \"%s\" is inteno product and in lan network\n", ip);

		/* add repeater's ip in the array */
		repeaters[i++] = strdup(ip);
		if (i >= MAX_REPEATERS)
			break;
	}

}

/* this function allocates memory. free it! when no longer needed */
char **collect_repeaters(void)
{
	int i;
	char **repeaters = NULL;

	repeaters = (char **)malloc(MAX_REPEATERS * sizeof(char *));
	if (!repeaters)
		goto out;

	for (i = 0; i < MAX_REPEATERS; i++)
		repeaters[i] = NULL;

	if (destination) {
		repeaters[0] = strdup(destination);
		goto out;
	}

	collect_intenos_on_the_lan(repeaters);

out:
	return repeaters;
}

FILE *fopen_wrapper(char *filename)
{
	int rv;
	FILE *file = NULL;
	long stdin_size = 0;

	if (filename) {
		file = fopen(filename, "r");
		goto out;
	}

	/* check if data is available on stdin */
	/*rv = fseek(stdin, 0L, SEEK_END);
	*if (rv == -1) {
	*	perror("fseek");
	*	goto out;
	*}
	*stdin_size = ftell(stdin);
	*rewind(stdin);

	*if (stdin_size > 0) {
	*	file = stdin;
	*	goto out;
	*}
	*/

	file = fopen(WIFICONTROL_DEFAULT_FILE, "r");

out:
	return file;
}

void send_data(char *ip)
{
	int sock, rv;
	struct sockaddr_in addr;
	FILE *file;
	char buffer[5];

	/* create a socket */
	sock = socket(AF_INET, SOCK_STREAM, 0 /* IP */);
	if (sock == -1) {
		perror("socket");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(WIFICONTROL_LISTENING_PORT);

	/* TODO connect etc */
	rv = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (rv == -1) {
		perror("connect");
		close(sock);
		return;
	}

	file = fopen_wrapper(filename);
	if (!file) {
		perror("fopen_wrapper");
		close(sock);
		return;
	}

	while (fgets(buffer, 5, file))
		printf("buffer: \"%s\"\n", buffer);
	if (ferror(file))
		perror("fgets");

	if (file && file != stdin)
		fclose(file);

	close(sock);
}

void router_mode(void)
{
	int i;
	char **repeaters = NULL;

	printf("Router mode\n");
	repeaters = collect_repeaters();

	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		printf("repeater[%d]: \"%s\"\n", i, repeaters[i]);

	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		send_data(repeaters[i]);

	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		free(repeaters[i]);
}

void repeater_mode(void)
{
	int sock, connection, rv, yes = 1;
	char buffer[100];
	struct sockaddr_in addr, remote_addr;
	socklen_t remote_addr_len;

	printf("Repeater mode\n");

	/* create a socket */
	sock = socket(AF_INET, SOCK_STREAM, 0 /* IP */);
	if (sock == -1) {
		perror("socket");
		return;
	}

	rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (rv == -1) {
		perror("setsockopt");
		close(sock);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(WIFICONTROL_LISTENING_PORT);

	rv = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (rv == -1) {
		perror("bind");
		close(sock);
		return;
	}

	rv = listen(sock, 5 /* MAXPENDING */);
	if (rv == -1) {
		perror("listen");
		close(sock);
		return;
	}

	while (1) {

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

		/* TODO check that remote_addr is the gateway and is inteno */

		memset(buffer, 0, 100);
		rv = recv(connection, buffer, 100, 0);
		if (rv < 0) {
			perror("recv");
			close(connection);
			continue;
		}

		printf("received: \"%s\"\n", buffer);

		close(connection);
	}

}

int main(int argc, char **argv)
{

	parse_args(argc, argv);

	printf("mode = %d\n", mode);

	if (mode == MODE_NONE)
		return 1;

	if (mode == MODE_ROUTER)
		router_mode();

	if (mode == MODE_REPEATER)
		repeater_mode();

	if (filename)
		free(filename);
	if (destination)
		free(destination);

	return 0;
}
