#ifndef PORT_H
#define PORT_H 1

typedef struct { /* Used by: questd.c and port.h */
	unsigned long rx_bytes;
	unsigned long rx_packets;
	unsigned long rx_errors;
	unsigned long tx_bytes;
	unsigned long tx_packets;
	unsigned long tx_errors;
} Statistic;

typedef struct { /* !!! used by questd.c and port.h */
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
	char name[16];
	char ssid[32];
	char device[32];
	Statistic stat;
	Client client[MAX_CLIENT];
} Port;

void get_port_name(Port *port);
void get_port_stats(Port *port);
void get_bridge_ports(char *network, char **ifname);
char *get_clients_onport(char *bridge, int portno);

#endif /* PORT */

