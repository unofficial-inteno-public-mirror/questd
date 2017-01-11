#define MAX_IFNAME 16

typedef struct iface {
	unsigned long rx_total, tx_total;
	unsigned long rx, tx;
	char name[MAX_IFNAME];
} iface;


void gather_traffic_data();
