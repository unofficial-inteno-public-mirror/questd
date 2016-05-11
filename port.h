#ifndef PORT_H
#define PORT_H 1

void get_port_name(Port *port);
void get_port_stats(Port *port);
void get_bridge_ports(char *network, char **ifname);
char *get_clients_onport(char *bridge, int portno);

#endif /* PORT */

