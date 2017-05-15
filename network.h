#define MAX_NETWORK	16
#define MAX_CLIENT	96
#define MAX_CLIENT_PER_PORT 64
#define MAX_PORT	16

#ifdef IOPSYS_BROADCOM
#include "broadcom.h"
#endif
#ifdef IOPSYS_MEDIATEK
#include "mediatek.h"
#endif

typedef struct {
	bool exists;
	bool connected;
	bool local;
	bool dhcp;
	char leasetime[24];
	char macaddr[24];
	char ipaddr[24];
	char hostname[64];
	char network[32];
	char device[32];
	bool wireless;
	bool repeated;
	char ethport[8];
	char wdev[8];
	struct wl_ether_addr assoclist[32];
	int nassoc;
} Client;

typedef struct {
	bool exists;
	bool connected;
	char leasetime[24];
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
	char linkspeed[64];
	Statistic stat;
	Client client[MAX_CLIENT_PER_PORT];
} Port;

typedef struct {
	bool exists;
	bool is_lan;
	bool defaultroute;
	char name[16];
	char type[16];
	char proto[16];
	char ipaddr[24];
	char netmask[24];
	char ifname[128];
	Port port[MAX_PORT];
	bool ports_populated;
} Network;

void populate_clients();
void load_networks();
void load_wireless();
void get_network_clients(Client *clnt);
void get_port_name(Port *port);
void get_port_stats(Port *port);
