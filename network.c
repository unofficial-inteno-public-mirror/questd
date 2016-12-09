/*
 * network -- provides router.network object of questd
 *
 * Copyright (C) 2012-2013 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: sukru.senli@inteno.se
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <libubox/blobmsg.h>
#include <libubus.h>
#include <uci.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "network.h"
#include "port.h"
#include "tools.h"
#include "wireless.h"

extern void recalc_sleep_time(bool calc, int toms);
extern bool arping(const char *targetIP, char *device, int toms);
extern bool ndisc6(char *ip6addr, char *ifname, char *macaddr);
extern void clear_macaddr(void);

enum {
	NETWORK_NAME,
	FAMILY,
	__NETWORK_MAX,
};

static const struct blobmsg_policy network_policy[__NETWORK_MAX] = {
	[NETWORK_NAME] = { .name = "network", .type = BLOBMSG_TYPE_STRING },
	[FAMILY] = { .name = "family", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy lease_policy[__NETWORK_MAX] = {
	[NETWORK_NAME] = { .name = "network", .type = BLOBMSG_TYPE_STRING },
	[FAMILY] = { .name = "family", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy family_policy[__NETWORK_MAX] = {
	[FAMILY] = { .name = "family", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	IP_ADDR,
	MAC_ADDR,
	__HOST_MAX,
};

static const struct blobmsg_policy host_policy[__HOST_MAX] = {
	[IP_ADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_STRING },
	[MAC_ADDR] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
};

static struct uci_context *uci_ctx;
static struct uci_package *uci_network, *uci_wireless;
static struct blob_buf bb;

static Network network[MAX_NETWORK];
static Client clients[MAX_CLIENT];
static Client clients_old[MAX_CLIENT];
static Client clients_new[MAX_CLIENT];
static Client6 clients6[MAX_CLIENT];

static int lease_time_count = 0;

static struct uci_package *
init_package(const char *config)
{
	struct uci_context *ctx = uci_ctx;
	struct uci_package *p = NULL;

	if (!ctx) {
		ctx = uci_alloc_context();
		uci_ctx = ctx;
	} else {
		p = uci_lookup_package(ctx, config);
		if (p)
			uci_unload(ctx, p);
	}

	if (uci_load(ctx, config, &p))
		return NULL;

	return p;
}

void
get_network_clients(Client *clnt)
{
	memcpy(clnt, clients, sizeof(clients));
}

static bool
wdev_already_there(const char *ifname, char *wdev)
{
	bool ret = false;
	char *token;
	char ifbuf[128];
	char *saveptr;

	strcpy(ifbuf, ifname);

	token = strtok_r(ifbuf, " ", &saveptr);
	while (token != NULL)
	{
		if(!strcmp(token, wdev)) {
			ret = true;
			break;
		}
		token = strtok_r (NULL, " ", &saveptr);
	}

	return ret;
}

static void
get_wifs(char *netname, const char *ifname, char **wifs)
{
	struct uci_element *e;
	const char *device = NULL;
	const char *network = NULL;
	char wdev[16];
	char wrl[64];
	const char *wdevs[2];		
	int vif, wno;

	wdevs[0] = "wl0";
	wdevs[1] = "wl1";

	*wifs = NULL;

	memset(wrl, '\0', sizeof(wrl));
	if((uci_wireless = init_package("wireless"))) {
		for(wno = 0; wno <= 1; wno++) {
			vif = 0;
			uci_foreach_element(&uci_wireless->sections, e) {
				struct uci_section *s = uci_to_section(e);

				if (!strcmp(s->type, "wifi-iface")) {
					device = uci_lookup_option_string(uci_ctx, s, "device");
					if(!device || strcmp(device, wdevs[wno]))
						continue;
					network = uci_lookup_option_string(uci_ctx, s, "network");
					if (network && device && !strcmp(network, netname)) {
						if (vif > 0)
							sprintf(wdev, "%s.%d", device, vif);
						else
							strcpy(wdev, device);

						if(wdev_already_there(ifname, wdev))
							continue;

						strcat(wrl, " ");
						strcat(wrl, wdev);
						*wifs = strdup(wrl);
					}
					vif++;
				}
			}
		}
	}
}

void
load_networks()
{
	struct uci_element *e;
	const char *is_lan = NULL;
	const char *type = NULL;
	const char *defaultroute = NULL;
	const char *proto = NULL;
	const char *ipaddr = NULL;
	const char *netmask = NULL;
	const char *ifname = NULL;
	char *wifs;
	int nno = 0;

	memset(network, '\0', sizeof(network));

	if((uci_network = init_package("network"))) {
		uci_foreach_element(&uci_network->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if(nno >= MAX_NETWORK) return;
			network[nno].exists = false;
			network[nno].ports_populated = false;
			if (!strcmp(s->type, "interface")) {
				is_lan = uci_lookup_option_string(uci_ctx, s, "is_lan");
				defaultroute = uci_lookup_option_string(uci_ctx, s, "defaultroute");
				type = uci_lookup_option_string(uci_ctx, s, "type");
				proto = uci_lookup_option_string(uci_ctx, s, "proto");
				ipaddr = uci_lookup_option_string(uci_ctx, s, "ipaddr");
				netmask = uci_lookup_option_string(uci_ctx, s, "netmask");
				ifname = uci_lookup_option_string(uci_ctx, s, "ifname");
				if(!(ifname))
					ifname = "";
				get_wifs(s->e.name, ifname, &wifs);
				if ((ifname && strcmp(ifname, "lo")) || wifs) {
					network[nno].exists = true;
					if(is_lan && !strcmp(is_lan, "1"))
						network[nno].is_lan = true;
					network[nno].name = s->e.name;
					if(defaultroute && !strcmp(defaultroute, "0"))
						network[nno].defaultroute = false;
					else
						network[nno].defaultroute = true;
					(type) ? (network[nno].type = type) : (network[nno].type = "");
					(proto) ? (network[nno].proto = proto) : (network[nno].proto = "");
					if(proto && !strcmp(network[nno].proto, "static")) {
						(ipaddr) ? (network[nno].ipaddr = ipaddr) : (network[nno].ipaddr = "");
						(netmask) ? (network[nno].netmask = netmask) : (network[nno].netmask = "");
					}
					if(wifs)
						sprintf(network[nno].ifname, "%s%s", ifname, wifs);
					else
						strcpy(network[nno].ifname, ifname);
					nno++;
					if (wifs)
						free(wifs);
				}
			}
		}
	}
}

static int
active_connections(char *ipaddr)
{
	FILE *f;
	int i;
	char *p, line[512];
	char *saveptr;
	int connum = 0;

	if ((f = fopen("/proc/net/nf_conntrack", "r")) != NULL)
	{
		while (fgets(line, sizeof(line) - 1, f))
		{
			for (i = 0, p = strtok_r(line, " ", &saveptr); p; i++, p = strtok_r(NULL, " ", &saveptr))
			{
				if (i == 6 && !strcmp(p+4, ipaddr))
					connum++;
			}
		}

		fclose(f);
	}

	return connum;
}

static void
match_client_to_network(Network *lan, char *ipaddr, bool *local, char *net, char *dev)
{
	if(!lan->ipaddr || !lan->netmask)
		return;

	struct in_addr ip, mask, snet, host, rslt;

	inet_pton(AF_INET, lan->ipaddr, &(ip.s_addr));
	inet_pton(AF_INET, lan->netmask, &(mask.s_addr));
	inet_pton(AF_INET, ipaddr, &(host.s_addr));

	snet.s_addr = (ip.s_addr & mask.s_addr);
	rslt.s_addr = (host.s_addr & mask.s_addr);

	if((snet.s_addr ^ rslt.s_addr) == 0) {
		*local = true;
		snprintf(net, 32, lan->name);
		if (lan->type && !strcmp(lan->type, "bridge"))
			snprintf(dev, 32, "br-%s", lan->name);
		else
			snprintf(dev, 32, lan->ifname);
	}
}

static void
handle_client(Client *clnt)
{
	int ip[4];
	int netno;

	clnt->local = false;
	if (sscanf(clnt->ipaddr, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) == 4) {
		for (netno=0; netno < MAX_NETWORK && network[netno].exists; netno++) {
			if (network[netno].is_lan) {
				match_client_to_network(&network[netno], clnt->ipaddr, &clnt->local, clnt->network, clnt->device);
				if (clnt->local)
					break;
			}
		}
	}
}

static void
populate_ports(Network *network)
{
	char bridge[32];
	char macaddr[2400];
	char *theports;
	char *prt, *mac;
	char *saveptr1, *saveptr2;
	int i = 1;
	int j, k, l;
	Port *port = (Port*)&network->port;
	
	sprintf(bridge, "br-%s", network->name);

	if (network->ports_populated)
		goto get_clients;

	get_bridge_ports(bridge, &theports);
	for (j = 0; j < MAX_PORT; j++)
		memset(&port[j], 0, sizeof(Port));

	prt = strtok_r(theports, " ", &saveptr1);
	while (prt != NULL)
	{
		if(strncmp(prt, "wl", 2) && strchr(prt, '.'))
			goto nextport;

		strncpy(port[i].device, prt, 32);
		get_port_name(&port[i]);
		if(strstr(port[i].device, "eth"))
			get_port_speed(port[i].linkspeed, port[i].device);
nextport:
		prt = strtok_r (NULL, " ", &saveptr1);
		i++;
	}
	if (theports)
		free(theports);
	
	network->ports_populated = true;
		
get_clients:	
	for(i=1; i < MAX_PORT; i++)
	{

		if(strlen(port[i].device)<2)
			continue;

		memset(&port[i].stat, '\0', sizeof(Statistic));
		for (j=0; port[i].client[j].exists; j++) {
			memset(&port[i].client[j], '\0', sizeof(Client));
		}

		get_port_stats(&port[i]);
		strncpy(macaddr, get_clients_onport(bridge, i), 2400);

		l = 0;
		if(network->is_lan) {
			for (k=0; k < MAX_CLIENT && clients[k].exists; k++) {
				if(l >= MAX_CLIENT) break;
				if (clients[k].connected && strstr(macaddr, clients[k].macaddr)) {
					port[i].client[l] = clients[k];
					l++;
				}
			}
		} else {
			mac = strtok_r(macaddr, " ", &saveptr2);
			while (mac != NULL)
			{
				if(l >= MAX_CLIENT) break;
				if(is_inteno_altered_macaddr(mac))
					goto nextmac;
				port[i].client[l].exists = true;
				strcpy(port[i].client[l].macaddr, mac);
				mac = strtok_r (NULL, " ", &saveptr2);
nextmac:
				l++;
			}	
		}
	}
}

static void dump_client(struct blob_buf *b, Client client)
{
#if IOPSYS_BROADCOM
	static char linkspeed[64];
	struct wl_sta_info sta_info;
	int bandwidth, channel, noise, rssi, snr, htcaps;

	if(client.wireless && !wl_get_stas_info(client.wdev, client.macaddr, &sta_info, &htcaps))
		return;
#endif
	int cno;

	blobmsg_add_string(b, "hostname", client.hostname);
	blobmsg_add_string(b, "ipaddr", client.ipaddr);
	blobmsg_add_string(b, "macaddr", client.macaddr);

	for (cno = 0; cno < MAX_CLIENT && clients6[cno].exists; cno++) {
		if(!strcasecmp(clients6[cno].macaddr, client.macaddr)) {
			blobmsg_add_string(b, "ip6addr", clients6[cno].ip6addr);
			blobmsg_add_string(b, "duid", clients6[cno].duid);
			break;
		}
	}

	blobmsg_add_string(b, "network", client.network);
	blobmsg_add_string(b, "device", client.device);
	blobmsg_add_u8(b, "dhcp", client.dhcp);
	blobmsg_add_u8(b, "connected", client.connected);
	if(client.connected)
		blobmsg_add_u32(b, "active_connections", active_connections(client.ipaddr));
	blobmsg_add_u8(b, "wireless", client.wireless);
#if IOPSYS_BROADCOM
	if(client.wireless) {
		wl_get_stas_info(client.wdev, client.macaddr, &sta_info, &htcaps);
		wl_get_bssinfo(client.wdev, &bandwidth, &channel, &noise);
		wl_get_rssi(client.wdev, client.macaddr, &rssi);
		snr = rssi - noise;

		blobmsg_add_string(b, "wdev", client.wdev);
		blobmsg_add_string(b, "frequency", (channel >= 36) ? "5GHz" : "2.4GHz");
		blobmsg_add_u32(b, "rssi", rssi);
		blobmsg_add_u32(b, "snr", snr);
		blobmsg_add_u32(b, "idle", sta_info.idle);
		blobmsg_add_u32(b, "in_network", sta_info.in);
		blobmsg_add_u8(b, "wme", (sta_info.flags & WL_STA_WME) ? true : false);
		blobmsg_add_u8(b, "ps", (sta_info.flags & WL_STA_PS) ? true : false);
		blobmsg_add_u8(b, "n_cap", (sta_info.flags & WL_STA_N_CAP) ? true : false);
		blobmsg_add_u8(b, "vht_cap", (sta_info.flags & WL_STA_VHT_CAP) ? true : false);
		blobmsg_add_u64(b, "tx_bytes", sta_info.tx_tot_bytes);
		blobmsg_add_u64(b, "rx_bytes", sta_info.rx_tot_bytes);
		blobmsg_add_u32(b, "tx_rate", (sta_info.tx_rate_fallback > sta_info.tx_rate) ? sta_info.tx_rate_fallback : sta_info.tx_rate);
		blobmsg_add_u32(b, "rx_rate", sta_info.rx_rate);
	} else if(client.connected) {
		if(!strncmp(client.ethport, "eth", 3)) {
			blobmsg_add_string(b, "ethport", client.ethport);
			get_port_speed(linkspeed, client.ethport);
			blobmsg_add_string(b, "linkspeed", linkspeed);
		} else {
			blobmsg_add_u8(b, "repeated", client.repeated);
		}
	}

	if(is_inteno_macaddr(client.macaddr)) {
		void *a, *t;
		int i = 0;
		int j = 0;
		char stamac[24];

		a = blobmsg_open_array(b, "assoclist");

		while (i < 32 && client.assoclist[i].octet[0] != 0)
		{
			strncpy(stamac, (char*) wl_ether_etoa(&(client.assoclist[i])), 24);
			t = blobmsg_open_table(b, "");
			blobmsg_add_string(b, "macaddr", stamac);
			for (j=0; j < MAX_CLIENT && clients[j].exists; j++) {
				if(!strcasecmp(clients[j].macaddr, (const char*) stamac)) {
					blobmsg_add_string(b, "hostname", clients[j].hostname);
					blobmsg_add_string(b, "ipaddr", clients[j].ipaddr);
					break;
				}
			}
			blobmsg_close_table(b, t);

			i++;
		}

		blobmsg_close_array(b, a);
	}
#endif
}

static void
router_dump_ports(struct blob_buf *b, char *interface)
{
	char output[64];

	if (!strlen(chrCmd(output, 64, "uci -q get network.%s.ifname", interface)))
		return;

	void *t, *c, *h, *s;
	int pno, i, j;
#if IOPSYS_BROADCOM
	int k, l;
#endif
	const char *ports[8];
	bool found = false;

	ports[0] = "LAN";
	ports[1] = "LAN1";
	ports[2] = "LAN2";
	ports[3] = "LAN3";
	ports[4] = "LAN4";
	ports[5] = "GbE";
	ports[6] = "WAN";
	ports[7] = "WLAN";

	Port *port;
	
	for (i = 0; i < MAX_NETWORK; i++) {
		if (network[i].exists && !strcmp(network[i].name, interface)) {
			populate_ports(&network[i]);
			port = (Port*)&network[i].port;
			found = true;
			break;
		}
	}
	
	if (!found)
		return;

	for (pno=0; pno<=7; pno++) {
		for (i = 1; i < MAX_PORT; i++) {
			if(strlen(port[i].device) < 2)
				continue;

			if(strcmp(port[i].name, ports[pno]))
				continue;
			t = blobmsg_open_table(b, port[i].device);
			if(!strncmp(port[i].device, "wl", 2) && strlen(port[i].ssid) > 0)
				blobmsg_add_string(b, "ssid", port[i].ssid);
			else {
				blobmsg_add_string(b, "name", port[i].name);
				blobmsg_add_string(b, "linkspeed", port[i].linkspeed);
			}
			c = blobmsg_open_array(b, "hosts");
			for(j=0; j < MAX_CLIENT_PER_PORT && port[i].client[j].exists; j++) {

			#if IOPSYS_BROADCOM
				for(k=0; k < MAX_CLIENT && clients[k].exists; k++) {
					if (is_inteno_macaddr(clients[k].macaddr)) {
						for(l=0; l < 32 && clients[k].assoclist[l].octet[0] != 0; l++) {
							if (!strcasecmp((char*) wl_ether_etoa(&(clients[k].assoclist[l])), port[i].client[j].macaddr))
								continue;
						}
					}
				}
			#endif

				port[i].client[j].connected = true;
				if(!strncmp(port[i].device, "wl", 2)) {
					strncpy(port[i].client[j].wdev, port[i].device, 8);
					port[i].client[j].wireless = true;
				} else {
					strncpy(port[i].client[j].ethport, port[i].device, 8);
					port[i].client[j].wireless = false;
				}

				h = blobmsg_open_table(b, "NULL");
				dump_client(b, port[i].client[j]);
				blobmsg_close_table(b, h);
			}
			blobmsg_close_array(b, c);
			s = blobmsg_open_table(b, "statistics");
			blobmsg_add_u64(b, "rx_packets", port[i].stat.rx_packets);
			blobmsg_add_u64(b, "rx_bytes", port[i].stat.rx_bytes);
			blobmsg_add_u64(b, "rx_errors", port[i].stat.rx_errors);				
			blobmsg_add_u64(b, "tx_packets", port[i].stat.tx_packets);
			blobmsg_add_u64(b, "tx_bytes", port[i].stat.tx_bytes);
			blobmsg_add_u64(b, "tx_errors", port[i].stat.tx_errors);
			blobmsg_close_table(b, s);
			blobmsg_close_table(b, t);
		}
	}
}

static void
network_dump_leases(struct blob_buf *b, char *leasenet, int family)
{
	void *t;
	char leasenum[16];
	int i;

	if (family == 4)
		for (i = 0; i < MAX_CLIENT && clients[i].exists; i++) {
			if (clients[i].dhcp && (leasenet == NULL || !strcmp(clients[i].network, leasenet))) {
				sprintf(leasenum, "lease-%d", i + 1);
				t = blobmsg_open_table(b, leasenum);
				blobmsg_add_string(b, "leasetime", clients[i].leasetime);
				blobmsg_add_string(b, "hostname", clients[i].hostname);
				blobmsg_add_string(b, "ipaddr", clients[i].ipaddr);
				blobmsg_add_string(b, "macaddr", clients[i].macaddr);
				blobmsg_add_string(b, "device", clients[i].device);
				blobmsg_add_u8(b, "connected", clients[i].connected);
				blobmsg_close_table(b, t);
			}
		}
	else if (family == 6)
		for (i = 0; i < MAX_CLIENT && clients6[i].exists; i++) {
			//if (clients[i].dhcp && !strcmp(clients[i].network, leasenet)) {
				sprintf(leasenum, "lease-%d", i + 1);
				t = blobmsg_open_table(b, leasenum);
				blobmsg_add_string(b, "leasetime", clients6[i].leasetime);
				blobmsg_add_string(b, "hostname", clients6[i].hostname);
				blobmsg_add_string(b, "ip6addr", clients6[i].ip6addr);
				blobmsg_add_string(b, "duid", clients6[i].duid);
				blobmsg_add_string(b, "macaddr", clients6[i].macaddr);
				blobmsg_add_string(b, "device", clients6[i].device);
				blobmsg_add_u8(b, "connected", clients6[i].connected);
				blobmsg_close_table(b, t);
			//}
		}
}


static void
router_dump_clients(struct blob_buf *b, bool connected, const char *mac)
{
	void *t;
	size_t len = strlen("client-") + strlen("4294967295") + 1;
	char clientnum[len];
	int num = 1;
	int i;

	if(mac){
		for(i = 0; i < MAX_CLIENT; i++){
			if(!clients[i].exists)
				return;
			if(strcmp(clients[i].macaddr, mac) == 0){
				dump_client(b, clients[i]);
				return;
			}
		}
	}

	for (i = 0; i < MAX_CLIENT && clients[i].exists; i++) {
		if (connected && !(clients[i].connected))
			continue;

		snprintf(clientnum, len, "client-%d", num);
		t = blobmsg_open_table(b, clientnum);
		dump_client(b, clients[i]);
		blobmsg_close_table(b, t);
		num++;
	}
}

static void
router_dump_clients6(struct blob_buf *b, bool connected)
{
	void *t;
	size_t len = strlen("client-") + strlen("4294967295") + 1;
	char clientnum[len];
	int num = 1;
	int i;

	for (i = 0; i < MAX_CLIENT && clients6[i].exists; i++) {
		if (connected && !(clients6[i].connected))
			continue;

		snprintf(clientnum, len, "client-%d", num);
		t = blobmsg_open_table(b, clientnum);
		blobmsg_add_string(b, "hostname", clients6[i].hostname);
		blobmsg_add_string(b, "ip6addr", clients6[i].ip6addr);
		blobmsg_add_string(b, "macaddr", clients6[i].macaddr);
		blobmsg_add_string(b, "duid", clients6[i].duid);
		blobmsg_add_string(b, "device", clients6[i].device);
		blobmsg_add_u8(b, "connected", clients6[i].connected);
		blobmsg_add_u8(b, "wireless", clients6[i].wireless);
		if(clients6[i].wireless) {
			blobmsg_add_string(b, "wdev", clients6[i].wdev);
		}
		blobmsg_close_table(b, t);
		num++;
	}
}

static void
host_dump_status(struct blob_buf *b, char *addr, bool byIP)
{
	int i;

	if(byIP) {
		for (i=0; i < MAX_CLIENT && clients[i].exists; i++)
			if(!strcmp(clients[i].ipaddr, addr)) {
				router_dump_clients(b, false, clients[i].macaddr);
				break;
			}
	}
	else {
		for (i=0; i < MAX_CLIENT && clients[i].exists; i++)
			if(!strcasecmp(clients[i].macaddr, addr)) {
				router_dump_clients(b, false, addr);
				break;
			}
	}
}
static void
get_hostname_from_config(const char *mac_in, char *hostname)
{
	struct uci_element *e;
	static struct uci_package *uci_dhcp;
	struct uci_section *s;
	const char *mac = NULL;
	const char *hname = NULL;

	if((uci_dhcp = init_package("dhcp"))) {
		uci_foreach_element(&uci_dhcp->sections, e) {
			s = uci_to_section(e);

			if (!strcmp(s->type, "host")) {
				mac = uci_lookup_option_string(uci_ctx, s, "mac");
				if(mac && strcasecmp(mac, mac_in) == 0){
					hname = uci_lookup_option_string(uci_ctx, s, "name");
					if(hname)
						strncpy(hostname, hname, 64);
				}
			}
		}
	}
}

static void
ipv4_clients()
{
	FILE *leases, *arpt;
	char line[256];
	int cno = 0;
	int lno = 0;
	int hw;
	int flag;
	char mask[256];
	int i, j;
	bool there;
	int toms = 1000;
#if IOPSYS_BROADCOM
	char assoclist[1280];
	char *saveptr1, *saveptr2;
	int ano = 0;
	char *token;
#endif
	char brindex[8];
	char output[1280];

	memset(clients_new, '\0', sizeof(clients));

	if ((leases = fopen("/var/dhcp.leases", "r"))) {
		while(fgets(line, sizeof(line), leases) != NULL)
		{
			if(cno >= MAX_CLIENT) break;
			remove_newline(line);
			clients[cno].exists = false;
			clients[cno].wireless = false;
			memset(clients[cno].hostname, '\0', sizeof(clients[cno].hostname));
			memset(clients[cno].ethport, '\0', sizeof(clients[cno].ethport));
			if (sscanf(line, "%s %s %s %s %s", clients[cno].leasetime, clients[cno].macaddr, clients[cno].ipaddr, clients[cno].hostname, mask) == 5) {

				if(!is_inteno_macaddr(clients[cno].macaddr))
					continue;

				get_hostname_from_config(clients[cno].macaddr, clients[cno].hostname);
				clients[cno].exists = true;
				clients[cno].dhcp = true;
				handle_client(&clients[cno]);
			#if IOPSYS_BROADCOM
				if((clients[cno].connected = wireless_sta(&clients[cno]))) {
					clients[cno].wireless = true;
				}
				else
			#endif
				{
					clients[cno].connected = false;
					clients[cno].repeated = true;

					if(strstr(clients[cno].device, "br-")) {
						strncpy(brindex, chrCmd(output, 8, "brctl showmacs %s | grep %s | awk '{print$1}'", clients[cno].device, clients[cno].macaddr), 8);
						if(strlen(brindex))
							strncpy(clients[cno].ethport, chrCmd(output, 8, "brctl showbr %s | sed -n '%dp' | awk '{print$NF}'", clients[cno].device, atoi(brindex) + 1), 8);
					}

					if(!strncmp(clients[cno].ethport, "eth", 3)) {
						clients[cno].connected = true;
						clients[cno].repeated = false;
					} else if(!(clients[cno].connected = arping(clients[cno].ipaddr, clients[cno].device, toms)))
						recalc_sleep_time(true, toms);
				}

			#if IOPSYS_BROADCOM
				if(clients[cno].connected) {
					memset(clients[cno].assoclist, '\0', 128);
					strncpy(assoclist, chrCmd(output, 1280, "wificontrol -a %s", clients[cno].ipaddr), 1280);

					ano = 0;
					token = strtok_r(assoclist, " ", &saveptr1);
					while (token != NULL)
					{
						wl_ether_atoe(token, &(clients[cno].assoclist[ano]));
						token = strtok_r (NULL, " ", &saveptr1);
						ano++;
					}
				}
			#endif

				cno++;
			}
		}
		fclose(leases);
	}

	if ((leases = fopen("/var/dhcp.leases", "r"))) {
		while(fgets(line, sizeof(line), leases) != NULL)
		{
			if(cno >= MAX_CLIENT) break;
			remove_newline(line);
			clients[cno].exists = false;
			clients[cno].wireless = false;
			memset(clients[cno].hostname, '\0', sizeof(clients[cno].hostname));
			memset(clients[cno].ethport, '\0', sizeof(clients[cno].ethport));
			if (sscanf(line, "%s %s %s %s %s", clients[cno].leasetime, clients[cno].macaddr, clients[cno].ipaddr, clients[cno].hostname, mask) == 5) {

				if(is_inteno_macaddr(clients[cno].macaddr))
					continue;

				get_hostname_from_config(clients[cno].macaddr, clients[cno].hostname);
				clients[cno].exists = true;
				clients[cno].dhcp = true;
				handle_client(&clients[cno]);

			#if IOPSYS_BROADCOM
				for (i=0; i < cno; i++) {
					for(j=0; j < 32 && clients[i].assoclist[j].octet[0] != 0; j++) {
						if (!strcasecmp((char*)wl_ether_etoa(&(clients[i].assoclist[j])), clients[cno].macaddr)) {
							clients[cno].repeated = true;
							clients[cno].connected = true;
							goto inc;
						}
					}
				}


				if((clients[cno].connected = wireless_sta(&clients[cno]))) {
					clients[cno].wireless = true;
				}
				else
			#endif
				{
					clients[cno].connected = false;
					clients[cno].repeated = true;

					if(strstr(clients[cno].device, "br-")) {
						strncpy(brindex, chrCmd(output, 8, "brctl showmacs %s | grep %s | awk '{print$1}'", clients[cno].device, clients[cno].macaddr), 8);
						if(strlen(brindex))
							strncpy(clients[cno].ethport, chrCmd(output, 8, "brctl showbr %s | sed -n '%dp' | awk '{print$NF}'", clients[cno].device, atoi(brindex) + 1), 8);
					}

					if(!strncmp(clients[cno].ethport, "eth", 3)) {
						clients[cno].connected = true;
						clients[cno].repeated = false;
					} else if(!(clients[cno].connected = arping(clients[cno].ipaddr, clients[cno].device, toms)))
						recalc_sleep_time(true, toms);
				}
#if IOPSYS_BROADCOM
inc:
#endif
				cno++;
			}
		}
		fclose(leases);
	}

	if ((arpt = fopen("/proc/net/arp", "r"))) {
		while(fgets(line, sizeof(line), arpt) != NULL)
		{
			if(cno >= MAX_CLIENT) break;
			remove_newline(line);
			there = false;
			clients[cno].exists = false;
			clients[cno].wireless = false;
			memset(clients[cno].hostname, '\0', sizeof(clients[cno].hostname));
			memset(clients[cno].ethport, '\0', sizeof(clients[cno].ethport));
			if ((lno > 0) && sscanf(line, "%s 0x%d 0x%d %s %s %s", clients[cno].ipaddr, &hw, &flag, clients[cno].macaddr, mask, clients[cno].device)) {
				for (i=0; i < cno; i++) {
					if (!strcmp(clients[cno].macaddr, clients[i].macaddr)) {
						if (clients[i].connected) {
							there = true;
							break;
						} else {
							strcpy(clients[cno].hostname, clients[i].hostname);
						}
					}
					if (!strcmp(clients[cno].ipaddr, clients[i].ipaddr)) {
						there = true;
						break;
					}
				}
				if (!there) {
					handle_client(&clients[cno]);
					if(clients[cno].local) {
						get_hostname_from_config(clients[cno].macaddr, clients[cno].hostname);
						clients[cno].exists = true;
						clients[cno].dhcp = false;
					#if IOPSYS_BROADCOM
						if((clients[cno].connected = wireless_sta(&clients[cno]))) {
							clients[cno].wireless = true;
						} else
					#endif
						{
							clients[cno].connected = false;
							clients[cno].repeated = true;

							if(strstr(clients[cno].device, "br-")) {
								strncpy(brindex, chrCmd(output, 8, "brctl showmacs %s | grep %s | awk '{print$1}'", clients[cno].device, clients[cno].macaddr), 8);
								if(strlen(brindex))
									strncpy(clients[cno].ethport, chrCmd(output, 8, "brctl showbr %s | sed -n '%dp' | awk '{print$NF}'", clients[cno].device, atoi(brindex) + 1), 8);
							}

							if(!strncmp(clients[cno].ethport, "eth", 3)) {
								clients[cno].connected = true;
								clients[cno].repeated = false;
							} else if(!(clients[cno].connected = arping(clients[cno].ipaddr, clients[cno].device, toms)))
								recalc_sleep_time(true, toms);
						}

					#if IOPSYS_BROADCOM
						if(clients[cno].connected && is_inteno_macaddr(clients[cno].macaddr)) {
							memset(clients[cno].assoclist, '\0', 128);
							strncpy(assoclist, chrCmd(output, 1280, "wificontrol -a %s", clients[cno].ipaddr), 1280);

							ano = 0;
							token = strtok_r(assoclist, " ", &saveptr2);
							while (token != NULL)
							{
								wl_ether_atoe(token, &(clients[cno].assoclist[ano]));
								token = strtok_r (NULL, " ", &saveptr2);
								ano++;
							}
						}
					#endif

						cno++;
					}
				}
			}
			lno++;
		}
		fclose(arpt);
	}

	memcpy(&clients_new, &clients, sizeof(clients));

	bool still_there;
	for(i=0; i < MAX_CLIENT && clients_old[i].exists; i++) {
		still_there = false;
		if(!clients_old[i].connected) continue;
		for(j=0; j < MAX_CLIENT && clients_new[j].exists; j++) {
			if(!clients_new[j].connected) continue;
			if(!strcmp(clients_old[i].macaddr, clients_new[j].macaddr)) {
				still_there = true;
				if(clients_old[i].wireless && clients_new[j].wireless && strcmp(clients_old[i].wdev, clients_new[j].wdev) != 0)
					runCmd("ubus send client '{\"action\":\"move\",\"from\":\"%s\",\"to\":\"%s\"}'", clients_old[i].wdev, clients_new[j].wdev);
				break;
			}
		}
		if(!still_there)
			runCmd("ubus send client '{\"action\":\"disconnect\",\"macaddr\":\"%s\"}'", clients_old[i].macaddr);
	}

	bool was_there;
	for(i=0; i < MAX_CLIENT && clients_new[i].exists; i++) {
		was_there = false;
		if(!clients_new[i].connected) continue;
		for(j=0; clients_old[j].exists; j++) {
			if(!clients_old[j].connected) continue;
			if(!strcmp(clients_new[i].macaddr, clients_old[j].macaddr)) {
				was_there = true;
				break;
			}
		}
		if(!was_there)
			runCmd("ubus send client '{\"action\":\"connect\",\"macaddr\":\"%s\"}'", clients_new[i].macaddr);
	}

	memcpy(&clients_old, &clients_new, sizeof(clients));
}

static void
ipv6_clients()
{
	FILE *hosts6;
	char line[512];
	int cno = 0;
	int iaid, id, length;
	int toms = 1000;
	char *p;

	if ((hosts6 = fopen("/tmp/hosts/odhcpd", "r"))) {
		while(fgets(line, sizeof(line), hosts6) != NULL)
		{
			if(cno >= MAX_CLIENT) break;
			remove_newline(line);
			clients6[cno].exists = false;
			clients6[cno].wireless = false;
			memset(clients6[cno].hostname, '\0', sizeof(clients[cno].hostname));
			if (sscanf(line, "# %s %s %x %s %s %x %d %s", clients6[cno].device, clients6[cno].duid, &iaid, clients6[cno].hostname, clients6[cno].leasetime, &id, &length, clients6[cno].ip6addr)) {
				clients6[cno].exists = true;
				clear_macaddr();
				if ((p = strchr(clients6[cno].ip6addr, '/'))) *p = 0;
				//if((clients6[cno].connected = ndisc (clients6[cno].hostname, clients6[cno].device, 0x8, 1, toms))) {
				if((clients6[cno].connected = ndisc6 (clients6[cno].ip6addr, clients6[cno].device, clients6[cno].macaddr))) {
					//sprintf(clients6[cno].macaddr, get_macaddr());
				#if IOPSYS_BROADCOM
					if (wireless_sta6(&clients6[cno])) {
						clients6[cno].wireless = true;
					}
				#endif
				} else
					recalc_sleep_time(true, toms);

				cno++;
			}
		}
		fclose(hosts6);
	}
}

static bool popc = true;

void
populate_clients()
{
	if (lease_time_count == 720) {
		lease_time_count = 0;
		memset(clients, '\0', sizeof(clients));
		memset(clients6, '\0', sizeof(clients6));
	}

	if (popc) {
	#if IOPSYS_BROADCOM
		wireless_assoclist();
	#endif
		ipv4_clients();
		ipv6_clients();
		popc = false;
	} else
		popc = true;

	lease_time_count++;
}

static int
quest_router_networks(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *t;
	int i;

	blob_buf_init(&bb, 0);
	for (i = 0; i < MAX_NETWORK && network[i].exists; i++) {
		t = blobmsg_open_table(&bb, network[i].name);
		blobmsg_add_u8(&bb, "is_lan", network[i].is_lan);
		blobmsg_add_string(&bb, "type", network[i].type);
		blobmsg_add_u8(&bb, "defaultroute", network[i].defaultroute);
		blobmsg_add_string(&bb, "proto", network[i].proto);
		if (!strcmp(network[i].proto, "static")) {
			blobmsg_add_string(&bb, "ipaddr", network[i].ipaddr);
			blobmsg_add_string(&bb, "netmask", network[i].netmask);
		}
		blobmsg_add_string(&bb, "ifname", network[i].ifname);
		blobmsg_close_table(&bb, t);
	}
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_clients(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__NETWORK_MAX];

	blobmsg_parse(family_policy, __NETWORK_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);

	if (tb[FAMILY] && blobmsg_get_u32(tb[FAMILY]) == 6)
		router_dump_clients6(&bb, false);
	else
		router_dump_clients(&bb, false, NULL);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_network_leases(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__NETWORK_MAX];
	bool nthere = false;
	int i;

	blobmsg_parse(lease_policy, __NETWORK_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[NETWORK_NAME]) {
		for (i=0; i < MAX_NETWORK && network[i].is_lan; i++)
			if(!strcmp(network[i].name, blobmsg_data(tb[NETWORK_NAME])))
				nthere = true;

		if (!(nthere))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	blob_buf_init(&bb, 0);
	network_dump_leases(&bb, (tb[NETWORK_NAME])?blobmsg_data(tb[NETWORK_NAME]):NULL, (tb[FAMILY])?blobmsg_get_u32(tb[FAMILY]):4);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

int
quest_router_ports(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__NETWORK_MAX];
	bool nthere = false;
	int i;

	blobmsg_parse(network_policy, __NETWORK_MAX, tb, blob_data(msg), blob_len(msg));
	
	if (!(tb[NETWORK_NAME]))
		return UBUS_STATUS_INVALID_ARGUMENT;
		
	for (i=0; i < MAX_NETWORK && network[i].exists; i++) {
		if(!strcmp(network[i].name, blobmsg_data(tb[NETWORK_NAME]))) {
			if(!strcmp(network[i].type, "bridge") && strcmp(network[i].proto, "dhcp")) {
				nthere = true;
				break;
			 }
		}
	}

	if (!(nthere))
		return UBUS_STATUS_INVALID_ARGUMENT;
	
	blob_buf_init(&bb, 0);
	router_dump_ports(&bb, blobmsg_data(tb[NETWORK_NAME]));
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

int
quest_host_status(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__HOST_MAX];

	blobmsg_parse(host_policy, __HOST_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[IP_ADDR]) && !(tb[MAC_ADDR]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&bb, 0);
	if (tb[IP_ADDR])
		host_dump_status(&bb, blobmsg_data(tb[IP_ADDR]), true);
	else
		host_dump_status(&bb, blobmsg_data(tb[MAC_ADDR]), false);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

int
quest_network_reload(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	load_networks();
#if IOPSYS_BROADCOM
	load_wireless();
#endif
	return 0;
}

struct ubus_method network_object_methods[] = {
	UBUS_METHOD_NOARG("dump", quest_router_networks),
	UBUS_METHOD_NOARG("clients", quest_router_clients),
	UBUS_METHOD("leases", quest_network_leases, lease_policy),
	UBUS_METHOD("ports", quest_router_ports, network_policy),
	UBUS_METHOD_NOARG("reload", quest_network_reload),
};

struct ubus_object_type network_object_type =
	UBUS_OBJECT_TYPE("network", network_object_methods);

struct ubus_object network_object = {
	.name = "router.network",
	.type = &network_object_type,
	.methods = network_object_methods,
	.n_methods = ARRAY_SIZE(network_object_methods),
};
