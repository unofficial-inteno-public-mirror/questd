#define CHUNK		128

struct fdb_entry
{
	u_int8_t mac_addr[6];
	u_int16_t port_no;
	unsigned char is_local;
};

void get_bridge_ports(char *bridge, char **ports);
char* get_clients_onport(char *bridge, int portno);
int get_port_speed(char *linkspeed, char *device);
