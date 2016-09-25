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
#ifdef IOPSYS_BROADCOM
	struct wl_ether_addr assoclist[32];
#endif
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
	const char *name;
	const char *type;
	const char *proto;
	const char *ipaddr;
	const char *netmask;
	char ifname[128];
	Port port[MAX_PORT];
	bool ports_populated;
} Network;

void populate_clients();
void load_networks();
void load_wireless();
void get_clients(Client *clnt);
void clear_clients();

int igmp_snooping_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

int ip_conntrack_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);
