//#define _GNU_SOURCE 

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <uci.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <libubus.h>

#include "dslstats.h"
#include "ndisc.h"
#include "port.h"

#if IOPSYS_BROADCOM
#include "broadcom.h" // WILL NOT BE NEEDED LATER
#endif

#define MAX_RADIO	4
#define MAX_VIF		8
#define MAX_NETWORK	16
#define MAX_CLIENT	128
#define MAX_PORT	8
#define MAX_USB		18
#define MAX_IGMP_ENTRY	128

typedef struct {
	const char *vif;
	const char *device;
	const char *ssid;
	const char *network;
} Wireless;

typedef struct {
	const char *name;
	const char *band;
	int frequency;
	const char *hwmodes[6];
	int channels[64];
	int deviceid;
	int bwcaps[4];
	bool is_ac;
} Radio;

typedef struct {
	bool brcm;
	bool wme;
	bool ps;
	bool nonerp;
	bool apsd_be;
	bool apsd_bk;
	bool apsd_vi;
	bool apsd_vo;
	bool n_cap;
	bool vht_cap;
	bool ampdu_cap;
	bool amsdu_cap;
	bool mimo_ps;
	bool mimo_rts;
	bool rifs_cap;
	bool dwds_cap;
	bool dwds_active;
	bool scbstats;
} Flags;

typedef struct {
	bool ldpc;
	bool bw40;
	bool gf;
	bool sgi20;
	bool sgi40;
	bool tx_stbc;
	bool rx_stbc;
	bool delayed_ba;
	bool intl40;
} HTCaps;

typedef struct {
	bool ldpc;
	bool sgi80;
	bool sgi160;
	bool tx_stbc;
	bool rx_stbc;
	bool su_bfr;
	bool su_bfe;
	bool mu_bfr;
	bool mu_bfe;
	bool txopps;
	bool htc_vht_cap;
} VHTCaps;

typedef struct {
	bool exists;
	bool connected;
	bool local;
	bool dhcp;
	char leaseno[24];
	char macaddr[24];
	char ipaddr[24];
	char hostname[64];
	char network[32];
	char device[32];
	bool wireless;
	char wdev[8];
} Client;

typedef struct {
	bool exists;
	char macaddr[24];
	char wdev[8];
} Sta;

typedef struct {
	bool exists;
	bool connected;
	char ip6addr[128];
	char macaddr[24];
	char hostname[64];
	char duid[64];
	char device[32];
	bool wireless;
	char wdev[8];
} Client6;

typedef struct {
	unsigned long rx_bytes;
	unsigned long rx_packets;
	unsigned long rx_errors;
	unsigned long tx_bytes;
	unsigned long tx_packets;
	unsigned long tx_errors;
} Statistic;

typedef struct {
	char name[16];
	char ssid[32];
	char device[32];
	Statistic stat;
	Client client[MAX_CLIENT];
} Port;

typedef struct {
	bool exists;
	bool is_lan;
	const char *name;
	const char *type;
	const char *proto;
	const char *ipaddr;
	const char *netmask;
	char ifname[128];
	Port port[MAX_PORT];
	bool ports_populated;
} Network;

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

typedef struct {
	char mount[64];
	char product[64];
	char no[8];
	char name[8];
	unsigned long size;
	char device[64];
	char manufacturer[64];
	char serial[64];
	char speed[64];
	char maxchild[64];
	char idproduct[64];
	char idvendor[64];
} USB;

typedef struct {
	bool exists;
	char bridge[32];
	char device[32];
	char srcdev[32];
	char tags[32];
	int lantci;
	int wantci;
	char group[16];
	char mode[32];
	char RxGroup[16];
	char source[16];
	char reporter[16];
	int timeout;
	int Index;
	int ExcludPt;

}IGMPTable;

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
void get_jif_val(jiffy_counts_t *p_jif);

