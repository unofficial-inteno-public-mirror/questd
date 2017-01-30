#define MAX_IFNAME 16
#define MAX_CLNAME 16

typedef struct iface {
	unsigned long rx_total, tx_total;
	unsigned long rx, tx;
	char name[MAX_IFNAME];
} iface;

typedef struct client {
	unsigned long rx_total, tx_total;
	unsigned long rx, tx;
	char name[MAX_CLNAME];
} client;

void gather_iface_traffic_data();
