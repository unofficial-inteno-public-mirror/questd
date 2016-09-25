//#define _GNU_SOURCE 

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <crypt.h>
#include <fcntl.h>

#include <uci.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <libubus.h>

#if IOPSYS_BROADCOM
#include "broadcom.h" // WILL NOT BE NEEDED LATER
#endif

#define MAX_RADIO	4
#define MAX_VIF		8
#define MAX_NETWORK	16
#define MAX_CLIENT	96
#define MAX_CLIENT_PER_PORT 64
#define MAX_PORT	16
#define MAX_USB		18
#define MAX_IGMP_ENTRY	128

typedef struct {
	char name[64];
	char *hardware;
	char *model;
	char *boardid;
	char *firmware;
	char *brcmver;
	char *filesystem;
	char *socmod;
	char *socrev;
	char *cfever;
	char *kernel;
	char *basemac;
	char *serialno;
	char date[64];
	char uptime[64];
	unsigned int localtime;
	unsigned int procs;
	unsigned int cpu;
} Router;

typedef struct {
	unsigned long total;
	unsigned long used;
	unsigned long free;
	unsigned long shared;
	unsigned long buffers;
} Memory;

typedef struct {
	char *auth;
	char *des;
	char *wpa;
} Key;

typedef struct {
	bool wifi;
	bool adsl;
        bool vdsl;
        bool voice;
        bool dect;
        int vports;
	int eports;
} Spec;

typedef struct jiffy_counts_t {
	unsigned long long usr, nic, sys, idle;
	unsigned long long iowait, irq, softirq, steal;
	unsigned long long total;
	unsigned long long busy;
} jiffy_counts_t;

struct fdb_entry
{
	u_int8_t mac_addr[6];
	u_int16_t port_no;
	unsigned char is_local;
};

void recalc_sleep_time(bool calc, int toms);
void init_db_hw_config(void);
bool arping(const char *target, char *device, int toms);
void get_jif_val(jiffy_counts_t *p_jif);
void dump_keys(Key *keys);
void dump_specs(Spec *spec);
bool ndisc6(char *ip6addr, char *ifname, char *macaddr);
void dump_static_router_info(Router *router);
void dump_hostname(Router *router);
void dump_sysinfo(Router *router, Memory *memory);
void dump_cpuinfo(Router *router, jiffy_counts_t *prev_jif, jiffy_counts_t *cur_jif);
int get_port_speed(char *linkspeed, char *device);
void get_bridge_ports(char *network, char **ports);
char *get_clients_onport(char *bridge, int portno);
void clear_macaddr(void);
char *get_macaddr(void);
bool ndisc (const char *name, const char *ifname, unsigned flags, unsigned retry, unsigned wait_ms);
