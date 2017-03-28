#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "tools.h"

#define MAX_REPEATERS (255)

char *file;
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
			file = strdup(optarg ? optarg : "");
			printf("file: \"%s\"\n", file ? file : "(NULL)");
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
	char lanname[32], lanip[17], lanmask[17];

	chrCmd(lanname, 32,
	"uci -q show network | grep is_lan | grep -v loopback | head -n 1");
	printf("lanname \"%s\"\n", lanname);

	chrCmd(lanip, 17, "uci -q get network.lan.ipaddr");
	printf("lanip \"%s\"\n", lanip);

	chrCmd(lanmask, 17, "uci -q get network.lan.netmask");
	printf("lanmask \"%s\"\n", lanmask);
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


void router_mode(void)
{
	int i;
	char **repeaters = NULL;

	printf("Router mode\n");
	repeaters = collect_repeaters();


	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		printf("repeater[%d]: \"%s\"\n", i, repeaters[i]);


	for (i = 0; i <= MAX_REPEATERS && repeaters[i]; i++)
		free(repeaters[i]);
}

void repeater_mode(void)
{

	printf("Repeater mode\n");

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

	if (file)
		free(file);
	if (destination)
		free(destination);

	return 0;
}
