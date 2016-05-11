/*
 * questd -- router info daemon for Inteno CPEs
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
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <libubus.h>

#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <shadow.h>
#include <unistd.h>

#include "questd.h"
#include "tools.h"
#include "port.h"
#include "ndisc.h"


typedef struct { /* Used by: questd.c */
	const char *vif;
	const char *device;
	const char *ssid;
	const char *network;
} Wireless;

typedef struct { /* Used by: questd.c */
	const char *name;
	const char *band;
	int frequency;
	const char *hwmodes[6];
	int channels[64];
	int deviceid;
	int bwcaps[4];
	bool is_ac;
} Radio;

typedef struct { /* Used by: questd.c */
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



#define DEFAULT_SLEEP	5000000

static struct uci_context *uci_ctx;
static struct uci_package *uci_network, *uci_wireless;
static struct ubus_context *ctx = NULL;
static struct blob_buf bb;
static const char *ubus_path;

#if IOPSYS_BROADCOM
static Radio radio[MAX_RADIO];
#endif
static Wireless wireless[MAX_VIF];
static Network network[MAX_NETWORK];
static Client clients[MAX_CLIENT];
static Client clients_old[MAX_CLIENT];
static Client clients_new[MAX_CLIENT];
static Client6 clients6[MAX_CLIENT];
#if IOPSYS_BROADCOM
static Sta stas[MAX_CLIENT];
#endif
static Router router;
static Memory memory;
static Key keys;
static Spec spec;
static USB usb[MAX_USB];

/* POLICIES */
enum {
	QUEST_NAME,
	__QUEST_MAX,
};

static const struct blobmsg_policy quest_policy[__QUEST_MAX] = {
	[QUEST_NAME] = { .name = "info", .type = BLOBMSG_TYPE_STRING },
};

enum {
	NETWORK_NAME,
	__NETWORK_MAX,
};

static const struct blobmsg_policy network_policy[__NETWORK_MAX] = {
	[NETWORK_NAME] = { .name = "network", .type = BLOBMSG_TYPE_STRING },
};

enum {
	RADIO_NAME,
	VIF_NAME,
	__WL_MAX,
};

static const struct blobmsg_policy wl_policy[__WL_MAX] = {
	[RADIO_NAME] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
	[VIF_NAME] = { .name = "vif", .type = BLOBMSG_TYPE_STRING },
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

enum {
	P_USER,
	P_PASSWORD,
	P_CURPASSWORD,
	__P_MAX
};

static const struct blobmsg_policy password_policy[__P_MAX] = {
	[P_USER]     = { .name = "user",     .type = BLOBMSG_TYPE_STRING },
	[P_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[P_CURPASSWORD] = { .name = "curpass", .type = BLOBMSG_TYPE_STRING }
};

enum {
	PIN,
	__PIN_MAX,
};

static const struct blobmsg_policy pin_policy[__PIN_MAX] = {
	[PIN] = { .name = "pin", .type = BLOBMSG_TYPE_STRING },
};
/* END POLICIES */

pthread_t tid[1];
pthread_mutex_t lock;
static long sleep_time = DEFAULT_SLEEP;
static bool popc = true;

static int
errno_status(void)
{
	switch (errno)
	{
	case EACCES:
		return UBUS_STATUS_PERMISSION_DENIED;

	case ENOTDIR:
		return UBUS_STATUS_INVALID_ARGUMENT;

	case ENOENT:
		return UBUS_STATUS_NOT_FOUND;

	case EINVAL:
		return UBUS_STATUS_INVALID_ARGUMENT;

	default:
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
}

void recalc_sleep_time(bool calc, int toms)
{
	long dec = toms * 1000;
	if (!calc)
		sleep_time = DEFAULT_SLEEP;
	else if(sleep_time >= dec)
		sleep_time -= dec;
}

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

static void 
system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static bool
wdev_already_there(const char *ifname, char *wdev)
{
	bool ret = false;
	char *token;
	char ifbuf[128];

	strcpy(ifbuf, ifname);

	token = strtok(ifbuf, " ");
	while (token != NULL)
	{
		if(!strcmp(token, wdev)) {
			ret = true;
			break;
		}
		token = strtok (NULL, " ");
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

static void
load_networks()
{
	struct uci_element *e;
	const char *is_lan = NULL;
	const char *type = NULL;
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

			network[nno].exists = false;
			network[nno].ports_populated = false;
			if (!strcmp(s->type, "interface")) {
				is_lan = uci_lookup_option_string(uci_ctx, s, "is_lan");
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
				}
			}
		}
	}
}

#if IOPSYS_BROADCOM
static void
load_wireless()
{
	struct uci_element *e;
	const char *device = NULL;
	const char *network = NULL;
	const char *ssid = NULL;
	char wdev[16];
	int rno = 0;
	int wno = 0;
	int vif;
	int vif0 = 0;
	int vif1 = 0;

	memset(wireless, '\0', sizeof(wireless));
	memset(radio, '\0', sizeof(radio));

	if((uci_wireless = init_package("wireless"))) {
		uci_foreach_element(&uci_wireless->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (!strcmp(s->type, "wifi-iface")) {
				device = uci_lookup_option_string(uci_ctx, s, "device");
				network = uci_lookup_option_string(uci_ctx, s, "network");
				ssid = uci_lookup_option_string(uci_ctx, s, "ssid");
				if (device) {
					wireless[wno].device = device;
					(network) ? (wireless[wno].network = network) : (wireless[wno].network = "");
					(ssid) ? (wireless[wno].ssid = ssid) : (wireless[wno].ssid = "");
					if (!strcmp(device, "wl0")) {
						vif = vif0;
						vif0++;
					} else {
						vif = vif1;
						vif1++;
					}
					if (vif > 0)
						sprintf(wdev, "%s.%d", device, vif);
					else
						strcpy(wdev, device);

					wireless[wno].vif = strdup(wdev);

					wno++;
				}
			} else if (!strcmp(s->type, "wifi-device")) {
				radio[rno].name = s->e.name;
				if(!(radio[rno].band = uci_lookup_option_string(uci_ctx, s, "band")))
					radio[rno].band = "b";
				radio[rno].frequency = !strcmp(radio[rno].band, "a") ? 5 : 2;
				wl_get_deviceid(radio[rno].name, &(radio[rno].deviceid));
				radio[rno].is_ac = false;
				if (radio[rno].deviceid && atoi(chrCmd("db -q get hw.%x.is_ac", radio[rno].deviceid)) == 1)
					radio[rno].is_ac = true;

				if(radio[rno].frequency == 2) {
					radio[rno].hwmodes[0] = "11b";
					radio[rno].hwmodes[1] = "11g";
					radio[rno].hwmodes[2] = "11bg";
					radio[rno].hwmodes[3] = "11n";
					radio[rno].bwcaps[0] = 20;
					radio[rno].bwcaps[1] = 40;
					radio[rno].bwcaps[2] = '\0';
				} else if (radio[rno].frequency == 5) {
					radio[rno].hwmodes[0] = "11a";
					radio[rno].hwmodes[1] = "11n";
					radio[rno].hwmodes[2] = '\0';
					radio[rno].hwmodes[3] = '\0';
					radio[rno].bwcaps[0] = 20;
					radio[rno].bwcaps[1] = 40;
					radio[rno].bwcaps[2] = 80;
					radio[rno].bwcaps[3] = '\0';
					if (radio[rno].is_ac)
						radio[rno].hwmodes[2] = "11ac";
				}

				wl_get_chanlist(radio[rno].name, radio[rno].channels);

				rno++;
			}
		}
	}
}
#endif /* IOPSYS_BROADCOM */

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
		for (netno=0; network[netno].exists; netno++) {
			if (network[netno].is_lan) {
				match_client_to_network(&network[netno], clnt->ipaddr, &clnt->local, clnt->network, clnt->device);
				if (clnt->local)
					break;
			}
		}
	}
}

#if IOPSYS_BROADCOM
static void
wireless_assoclist()
{
	struct wl_maclist *macs = NULL;
	int sno = 0;
	int i, j;

	memset(stas, '\0', sizeof(stas));

	for (i = 0; wireless[i].device; i++) {
		if ((macs = wl_read_assoclist(wireless[i].vif)) != NULL)
		{
			for (j = 0; j < macs->count; j++)
			{
				stas[sno].exists = true;
				sprintf(stas[sno].macaddr, "%02X:%02X:%02X:%02X:%02X:%02X",
					macs->ea[j].octet[0], macs->ea[j].octet[1], macs->ea[j].octet[2],
					macs->ea[j].octet[3], macs->ea[j].octet[4], macs->ea[j].octet[5]
				);
				strcpy(stas[sno].wdev, wireless[i].vif);
				sno++;
			}

			free(macs);
		}
	}
}

static bool
wireless_sta(Client *clnt)
{
	bool there = false;
	int i = 0;
	while(stas[i].exists) {
		if (!strcasecmp(stas[i].macaddr, clnt->macaddr)) {
			there = true;
			strncpy(clnt->wdev, stas[i].wdev, sizeof(clnt->wdev));
			break;
		}
		i++;
	}
	return there;
}

static bool
wireless_sta6(Client6 *clnt)
{
	bool there = false;
	int i = 0;

	while(stas[i].exists) {
		if (!strcasecmp(stas[i].macaddr, clnt->macaddr)) {
			there = true;
			strncpy(clnt->wdev, stas[i].wdev, sizeof(clnt->wdev));
			break;
		}
		i++;
	}
	return there;
}

#if 0 /* Unused */
static int
active_connections(char *ipaddr)
{
	FILE *f;
	int i;
	char *p, line[512];
	int connum = 0;

	if ((f = fopen("/proc/net/nf_conntrack", "r")) != NULL)
	{
		while (fgets(line, sizeof(line) - 1, f))
		{
			for (i = 0, p = strtok(line, " "); p; i++, p = strtok(NULL, " "))
			{
				if (i == 6 && !strcmp(p+4, ipaddr))
					connum++;
			}
		}

		fclose(f);
	}

	return connum;
}
#endif
#endif

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

	memset(clients_new, '\0', sizeof(clients));

	if ((leases = fopen("/var/dhcp.leases", "r"))) {
		while(fgets(line, sizeof(line), leases) != NULL)
		{
			remove_newline(line);
			clients[cno].exists = false;
			clients[cno].wireless = false;
			memset(clients[cno].hostname, '\0', sizeof(clients[cno].hostname));
			if (sscanf(line, "%s %s %s %s %s", clients[cno].leaseno, clients[cno].macaddr, clients[cno].ipaddr, clients[cno].hostname, mask) == 5) {
				clients[cno].exists = true;
				clients[cno].dhcp = true;
				handle_client(&clients[cno]);
			#if IOPSYS_BROADCOM
				if((clients[cno].connected = wireless_sta(&clients[cno]))) {
					clients[cno].wireless = true;
				}
				else
			#endif
				if(!(clients[cno].connected = arping(clients[cno].ipaddr, clients[cno].device, toms)))
					recalc_sleep_time(true, toms);

				cno++;
			}
		}
		fclose(leases);
	}

	if ((arpt = fopen("/proc/net/arp", "r"))) {
		while(fgets(line, sizeof(line), arpt) != NULL)
		{
			remove_newline(line);
			there = false;
			clients[cno].exists = false;
			clients[cno].wireless = false;
			memset(clients[cno].hostname, '\0', sizeof(clients[cno].hostname));
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
						clients[cno].exists = true;
						clients[cno].dhcp = false;
					#if IOPSYS_BROADCOM
						if((clients[cno].connected = wireless_sta(&clients[cno]))) {
							clients[cno].wireless = true;
						} else
					#endif
						if(!(clients[cno].connected = arping(clients[cno].ipaddr, clients[cno].device, toms)))
							recalc_sleep_time(true, toms);

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
	for(i=0; clients_old[i].exists; i++) {
		still_there = false;
		if(!clients_old[i].connected) continue;
		for(j=0; clients_new[j].exists; j++) {
			if(!clients_new[j].connected) continue;
			if(!strcmp(clients_old[i].macaddr, clients_new[j].macaddr)) {
				still_there = true;
				break;
			}
		}
		if(!still_there)
			runCmd("ubus send client '{\"action\":\"disconnect\",\"macaddr\":\"%s\"}'", clients_old[i].macaddr);
	}

	bool was_there;
	for(i=0; clients_new[i].exists; i++) {
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
	int iaid, ts, id, length;
	int toms = 500;

	if ((hosts6 = fopen("/tmp/hosts/odhcpd", "r"))) {
		while(fgets(line, sizeof(line), hosts6) != NULL)
		{
			remove_newline(line);
			clients6[cno].exists = false;
			clients6[cno].wireless = false;
			memset(clients6[cno].hostname, '\0', sizeof(clients[cno].hostname));
			if (sscanf(line, "# %s %s %x %s %d %x %d %s", clients6[cno].device, clients6[cno].duid, &iaid, clients6[cno].hostname, &ts, &id, &length, clients6[cno].ip6addr)) {
				clients6[cno].exists = true;
				clear_macaddr();
				if((clients6[cno].connected = ndisc (clients6[cno].hostname, clients6[cno].device, 0x8, 1, toms))) {
					sprintf(clients6[cno].macaddr, get_macaddr());
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

static void
populate_clients()
{
	if (popc) {
	#if IOPSYS_BROADCOM
		wireless_assoclist();
	#endif
		ipv4_clients();
		ipv6_clients();
		popc = false;
	} else
		popc = true;
}

static void
populate_ports(Network *network)
{
	char bridge[32];
	char macaddr[2400];
	char *theports;
	char *prt, *mac;
	int i = 1;
	int j, k, l;
	Port *port = (Port*)&network->port;
	
	sprintf(bridge, "br-%s", network->name);

	if (network->ports_populated)
		goto get_clients;

	get_bridge_ports(bridge, &theports);
	memset(port, '\0', sizeof(Port));

	prt = strtok(theports, " ");
	while (prt != NULL)
	{
		strcpy(port[i].device, prt);
		get_port_name(&port[i]);
		prt = strtok (NULL, " ");
		i++;
	}
	
	network->ports_populated = true;
		
get_clients:	
	for(i=1; strlen(port[i].device)>2; i++)
	{				
		memset(&port[i].stat, '\0', sizeof(Statistic));
		for (j=0; port[i].client[j].exists; j++) {
			memset(&port[i].client[j], '\0', sizeof(Client));
		}
		
		get_port_stats(&port[i]);
		strncpy(macaddr, get_clients_onport(bridge, i), 2400);

		l = 0;
		if(network->is_lan) {
			for (k=0; clients[k].exists; k++) {
				if (strstr(macaddr, clients[k].macaddr) && clients[k].connected) {
					port[i].client[l] = clients[k];
					l++;
				}
			}
		} else {
			mac = strtok(macaddr, " ");
			while (mac != NULL)
			{
				port[i].client[l].exists = true;
				strcpy(port[i].client[l].macaddr, mac);
				mac = strtok (NULL, " ");
				l++;
			}	
		}
	}
}

static void
router_dump_specs(struct blob_buf *b, bool table)
{
	void *t;

	if (table) t = blobmsg_open_table(b, "specs");
	blobmsg_add_u8(b, "wifi", spec.wifi);
	blobmsg_add_u8(b, "adsl", spec.adsl);
	blobmsg_add_u8(b, "vdsl", spec.vdsl);
	blobmsg_add_u8(b, "voice", spec.voice);
	blobmsg_add_u32(b, "voice_ports", spec.vports);
	blobmsg_add_u32(b, "eth_ports", spec.eports);
	if (table) blobmsg_close_table(b, t);
}

static void
router_dump_keys(struct blob_buf *b, bool table)
{
	void *t;

	if (table) t = blobmsg_open_table(b, "keys");
	blobmsg_add_string(b, "auth", keys.auth);
	blobmsg_add_string(b, "des", keys.des);
	blobmsg_add_string(b, "wpa", keys.wpa);
	if (table) blobmsg_close_table(b, t);
}

static void
router_dump_system_info(struct blob_buf *b, bool table)
{
	void *t;

	if (table) t = blobmsg_open_table(b, "system");
	blobmsg_add_string(b, "name", router.name);
	blobmsg_add_string(b, "hardware", router.hardware);
	blobmsg_add_string(b, "model", router.model);
	blobmsg_add_string(b, "boardid", router.boardid);
	blobmsg_add_string(b, "firmware", router.firmware);
	blobmsg_add_string(b, "brcmver", router.brcmver);
	blobmsg_add_string(b, "filesystem", router.filesystem);
	blobmsg_add_string(b, "socmod", router.socmod);
	blobmsg_add_string(b, "socrev", router.socrev);
	blobmsg_add_string(b, "cfever", router.cfever);
	blobmsg_add_string(b, "kernel", router.kernel);
	blobmsg_add_string(b, "basemac", router.basemac);
	blobmsg_add_string(b, "serialno", router.serialno);
	blobmsg_add_u32(b, "localtime", router.localtime);
	blobmsg_add_string(b, "date", router.date);
	blobmsg_add_string(b, "uptime", router.uptime);
	blobmsg_add_u32(b, "procs", router.procs);
	blobmsg_add_u32(b, "cpu_per", router.cpu);
	if (table) blobmsg_close_table(b, t);
}

static void
router_dump_memory_info(struct blob_buf *b, bool table)
{
	void *t;

	if (table) t = blobmsg_open_table(b, "memoryKB");
	blobmsg_add_u64(b, "total", memory.total);
	blobmsg_add_u64(b, "used", memory.used);
	blobmsg_add_u64(b, "free", memory.free);
	blobmsg_add_u64(b, "shared", memory.shared);
	blobmsg_add_u64(b, "buffers", memory.buffers);
	if (table) blobmsg_close_table(b, t);
}

static void
router_dump_networks(struct blob_buf *b)
{
	void *t;
	int i;

	for (i = 0; i < MAX_NETWORK; i++) {
		if (!network[i].exists)
			break;
		t = blobmsg_open_table(b, network[i].name);
		blobmsg_add_u8(b, "is_lan", network[i].is_lan);
		blobmsg_add_string(b, "type", network[i].type);
		blobmsg_add_string(b, "proto", network[i].proto);
		if (!strcmp(network[i].proto, "static")) {
			blobmsg_add_string(b, "ipaddr", network[i].ipaddr);
			blobmsg_add_string(b, "netmask", network[i].netmask);
		}
		blobmsg_add_string(b, "ifname", network[i].ifname);
		blobmsg_close_table(b, t);
	}
}

static void
router_dump_clients(struct blob_buf *b, bool connected)
{
	void *t;
	char clientnum[10];
	int num = 1;
	int i;

	struct wl_sta_info sta_info;
	int bandwidth, channel, noise, rssi, snr;
	int htcaps;

	for (i = 0; i < MAX_CLIENT; i++) {
		if (!clients[i].exists)
			break;

		if (connected && !(clients[i].connected))
			continue;

		sprintf(clientnum, "client-%d", num);
		t = blobmsg_open_table(b, clientnum);
		blobmsg_add_string(b, "hostname", clients[i].hostname);
		blobmsg_add_string(b, "ipaddr", clients[i].ipaddr);
		blobmsg_add_string(b, "macaddr", clients[i].macaddr);
		blobmsg_add_string(b, "network", clients[i].network);
		blobmsg_add_string(b, "device", clients[i].device);
		blobmsg_add_u8(b, "dhcp", clients[i].dhcp);
		blobmsg_add_u8(b, "connected", clients[i].connected);
		blobmsg_add_u8(b, "wireless", clients[i].wireless);
#if IOPSYS_BROADCOM
		if(clients[i].wireless) {
			wl_get_stas_info(clients[i].wdev, clients[i].macaddr, &sta_info, &htcaps);
			wl_get_bssinfo(clients[i].wdev, &bandwidth, &channel, &noise);
			wl_get_rssi(clients[i].wdev, clients[i].macaddr, &rssi);
			snr = rssi - noise;

			blobmsg_add_string(b, "wdev", clients[i].wdev);
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
		}
#endif
		blobmsg_close_table(b, t);
		num++;
	}
}

static void
router_dump_clients6(struct blob_buf *b, bool connected)
{
	void *t;
	char clientnum[10];
	int num = 1;
	int i;

	for (i = 0; i < MAX_CLIENT; i++) {
		if (!clients6[i].exists)
			break;

		if (connected && !(clients6[i].connected))
			continue;

		sprintf(clientnum, "client-%d", num);
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
router_dump_stas(struct blob_buf *b, char *wname, bool vif)
{
	void *t, *f, *h, *v, *r, *s;
	char compare[8];
	char stanum[8];
	int num = 1;
	int i, j;

	struct wl_sta_info sta_info;
	int bandwidth, channel, noise, rssi, snr;
	int htcaps;

	for (i = 0; i < MAX_CLIENT; i++) {
		if (!clients[i].exists)
			break;
		if (!(clients[i].wireless))
			continue;

		if(wname) {
			memset(compare, '\0', sizeof(compare));
			if (vif)
				strcpy(compare, clients[i].wdev);
			else
				strncpy(compare, clients[i].wdev, 3);

			if (strcmp(compare, wname))
				continue;
		}

		wl_get_stas_info(clients[i].wdev, clients[i].macaddr, &sta_info, &htcaps);
		wl_get_bssinfo(clients[i].wdev, &bandwidth, &channel, &noise);
		wl_get_rssi(clients[i].wdev, clients[i].macaddr, &rssi);
		snr = rssi - noise;
		sta_info.ht_capabilities = htcaps;

		sprintf(stanum, "sta-%d", num);
		t = blobmsg_open_table(b, stanum);
		blobmsg_add_string(b, "hostname", clients[i].hostname);
		blobmsg_add_string(b, "ipaddr", clients[i].ipaddr);
		blobmsg_add_string(b, "macaddr", clients[i].macaddr);
		blobmsg_add_string(b, "network", clients[i].network);
		blobmsg_add_u8(b, "dhcp", clients[i].dhcp);
		if(strstr(clients[i].device, "br-"))
			blobmsg_add_string(b, "bridge", clients[i].device);
#if IOPSYS_BROADCOM
		blobmsg_add_string(b, "wdev", clients[i].wdev);
		blobmsg_add_string(b, "frequency", (channel >= 36) ? "5GHz" : "2.4GHz");
		blobmsg_add_u32(b, "rssi", rssi);
		blobmsg_add_u32(b, "snr", snr);
		blobmsg_add_u32(b, "idle", sta_info.idle);
		blobmsg_add_u32(b, "in_network", sta_info.in);

		f = blobmsg_open_table(b, "flags");
		blobmsg_add_u8(b, "brcm", (sta_info.flags & WL_STA_BRCM) ? true : false);
		blobmsg_add_u8(b, "wme", (sta_info.flags & WL_STA_WME) ? true : false);
		blobmsg_add_u8(b, "ps", (sta_info.flags & WL_STA_PS) ? true : false);
		blobmsg_add_u8(b, "no_erp", (sta_info.flags & WL_STA_NONERP) ? true : false);
		blobmsg_add_u8(b, "apsd_be", (sta_info.flags & WL_STA_APSD_BE) ? true : false);
		blobmsg_add_u8(b, "apsd_bk", (sta_info.flags & WL_STA_APSD_BK) ? true : false);
		blobmsg_add_u8(b, "apsd_vi", (sta_info.flags & WL_STA_APSD_VI) ? true : false);
		blobmsg_add_u8(b, "apsd_vo", (sta_info.flags & WL_STA_APSD_VO) ? true : false);
		blobmsg_add_u8(b, "n_cap", (sta_info.flags & WL_STA_N_CAP) ? true : false);
		blobmsg_add_u8(b, "vht_cap", (sta_info.flags & WL_STA_VHT_CAP) ? true : false);
		blobmsg_add_u8(b, "ampdu", (sta_info.flags & WL_STA_AMPDU_CAP) ? true : false);
		blobmsg_add_u8(b, "amsdu", (sta_info.flags & WL_STA_AMSDU_CAP) ? true : false);
		blobmsg_add_u8(b, "mimo_ps", (sta_info.flags & WL_STA_MIMO_PS) ? true : false);
		blobmsg_add_u8(b, "mimo_ps_rts", (sta_info.flags & WL_STA_MIMO_RTS) ? true : false);
		blobmsg_add_u8(b, "rifs", (sta_info.flags & WL_STA_RIFS_CAP) ? true : false);
		blobmsg_add_u8(b, "dwds_cap", (sta_info.flags & WL_STA_DWDS_CAP) ? true : false);
		blobmsg_add_u8(b, "dwds_active", (sta_info.flags & WL_STA_DWDS) ? true : false);
		blobmsg_close_table(b, f);

		h = blobmsg_open_table(b, "htcaps");
		blobmsg_add_u8(b, "ldpc", (sta_info.ht_capabilities & WL_STA_CAP_LDPC_CODING) ? true : false);
		blobmsg_add_u8(b, "bw40", (sta_info.ht_capabilities & WL_STA_CAP_40MHZ) ? true : false);
		blobmsg_add_u8(b, "gf", (sta_info.ht_capabilities & WL_STA_CAP_GF) ? true : false);
		blobmsg_add_u8(b, "sgi20", (sta_info.ht_capabilities & WL_STA_CAP_SHORT_GI_20) ? true : false);
		blobmsg_add_u8(b, "sgi40", (sta_info.ht_capabilities & WL_STA_CAP_SHORT_GI_40) ? true : false);
		blobmsg_add_u8(b, "stbc_tx", (sta_info.ht_capabilities & WL_STA_CAP_TX_STBC) ? true : false);
		blobmsg_add_u8(b, "stbc_rx", (sta_info.ht_capabilities & WL_STA_CAP_RX_STBC_MASK) ? true : false);
		blobmsg_add_u8(b, "d_block_ack", (sta_info.ht_capabilities & WL_STA_CAP_DELAYED_BA) ? true : false);
		blobmsg_add_u8(b, "intl40", (sta_info.ht_capabilities & WL_STA_CAP_40MHZ_INTOLERANT) ? true : false);
		blobmsg_close_table(b, h);

		if (sta_info.flags & WL_STA_VHT_CAP) {
			v = blobmsg_open_table(b, "vhtcaps");
			blobmsg_add_u8(b, "ldpc", (sta_info.vht_flags & WL_STA_VHT_LDPCCAP) ? true : false);
			blobmsg_add_u8(b, "sgi80", (sta_info.vht_flags & WL_STA_SGI80) ? true : false);
			blobmsg_add_u8(b, "sgi160", (sta_info.vht_flags & WL_STA_SGI160) ? true : false);
			blobmsg_add_u8(b, "stbc_tx", (sta_info.vht_flags & WL_STA_VHT_TX_STBCCAP) ? true : false);
			blobmsg_add_u8(b, "stbc_rx", (sta_info.vht_flags & WL_STA_VHT_RX_STBCCAP) ? true : false);
			blobmsg_add_u8(b, "su_bfr", (sta_info.vht_flags & WL_STA_SU_BEAMFORMER) ? true : false);
			blobmsg_add_u8(b, "su_bfe", (sta_info.vht_flags & WL_STA_SU_BEAMFORMEE) ? true : false);
			blobmsg_add_u8(b, "mu_bfr", (sta_info.vht_flags & WL_STA_MU_BEAMFORMER) ? true : false);
			blobmsg_add_u8(b, "mu_bfe", (sta_info.vht_flags & WL_STA_MU_BEAMFORMEE) ? true : false);
			blobmsg_add_u8(b, "txopps", (sta_info.vht_flags & WL_STA_VHT_TXOP_PS) ? true : false);
			blobmsg_add_u8(b, "vht_htc", (sta_info.vht_flags & WL_STA_HTC_VHT_CAP) ? true : false);
			blobmsg_close_table(b, v);
		}

		if (sta_info.flags & WL_STA_SCBSTATS)
		{
			s = blobmsg_open_table(b, "scbstats");
			blobmsg_add_u32(b, "tx_total_pkts", sta_info.tx_tot_pkts);
			blobmsg_add_u64(b, "tx_total_bytes", sta_info.tx_tot_bytes);
			blobmsg_add_u32(b, "tx_ucast_pkts", sta_info.tx_pkts);
			blobmsg_add_u64(b, "tx_ucast_bytes", sta_info.tx_ucast_bytes);
			blobmsg_add_u32(b, "tx_mcast_bcast_pkts", sta_info.tx_mcast_pkts);
			blobmsg_add_u64(b, "tx_mcast_bcast_bytes", sta_info.tx_mcast_bytes);
			blobmsg_add_u32(b, "tx_failures", sta_info.tx_failures);
			blobmsg_add_u32(b, "rx_data_pkts", sta_info.rx_tot_pkts);
			blobmsg_add_u64(b, "rx_data_bytes", sta_info.rx_tot_bytes);
			blobmsg_add_u32(b, "rx_ucast_pkts", sta_info.rx_ucast_pkts);
			blobmsg_add_u64(b, "rx_ucast_bytes", sta_info.rx_ucast_bytes);
			blobmsg_add_u32(b, "rx_mcast_bcast_pkts", sta_info.rx_mcast_pkts);
			blobmsg_add_u64(b, "rx_mcast_bcast_bytes", sta_info.rx_mcast_bytes);
			blobmsg_add_u32(b, "rate_of_last_tx_pkt", (sta_info.tx_rate_fallback > sta_info.tx_rate) ? sta_info.tx_rate_fallback : sta_info.tx_rate);
			blobmsg_add_u32(b, "rate_of_last_rx_pkt", sta_info.rx_rate);
			blobmsg_add_u32(b, "rx_decrypt_succeeds", sta_info.rx_decrypt_succeeds);
			blobmsg_add_u32(b, "rx_decrypt_failures", sta_info.rx_decrypt_failures);
			blobmsg_add_u32(b, "tx_data_pkts_retried", sta_info.tx_pkts_retried);
			blobmsg_add_u32(b, "tx_total_pkts_sent", sta_info.tx_pkts_total);
			blobmsg_add_u32(b, "tx_pkts_retries", sta_info.tx_pkts_retries);
			blobmsg_add_u32(b, "tx_pkts_retry_exhausted", sta_info.tx_pkts_retry_exhausted);
			blobmsg_add_u32(b, "tx_fw_total_pkts_sent", sta_info.tx_pkts_fw_total);
			blobmsg_add_u32(b, "tx_fw_pkts_retries", sta_info.tx_pkts_fw_retries);
			blobmsg_add_u32(b, "tx_fw_pkts_retry_exhausted", sta_info.tx_pkts_fw_retry_exhausted);
			blobmsg_add_u32(b, "rx_total_pkts_retried", sta_info.rx_pkts_retried);
			blobmsg_close_table(b, s);

			r = blobmsg_open_array(b, "rssi_per_antenna");
			for (j = 0; sta_info.rssi[j]; j++)
				blobmsg_add_u32(b, "", sta_info.rssi[j]);			
			blobmsg_close_array(b, r);
		}
#endif
		blobmsg_close_table(b, t);
		num++;
	}
}

static void
router_dump_usbs(struct blob_buf *b)
{
	DIR *dir;
	struct dirent *ent;
	void *t;
	int uno = 0;

	memset(usb, '\0', sizeof(usb));
	if ((dir = opendir ("/sys/bus/usb/devices")) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
				continue;
			if(strchr(ent->d_name, ':') || strstr(ent->d_name, "usb"))
				continue;

			dump_usb_info(&usb[uno], ent->d_name);

			if(strlen(usb[uno].product) < 1)
				continue;

			t = blobmsg_open_table(b, usb[uno].name);
			blobmsg_add_string(b, "idproduct", usb[uno].idproduct);
			blobmsg_add_string(b, "idvendor", usb[uno].idvendor);
			blobmsg_add_string(b, "product", usb[uno].product);
			blobmsg_add_string(b, "speed", usb[uno].speed);
			if (usb[uno].maxchild && strcmp(usb[uno].maxchild, "0")) {
				blobmsg_add_u32(b, "maxchild", atoi(usb[uno].maxchild));
			}
			else {
				blobmsg_add_string(b, "manufacturer", usb[uno].manufacturer);
				blobmsg_add_string(b, "serial", usb[uno].serial);
				if(strlen(usb[uno].device) > 1) {
					blobmsg_add_string(b, "device", usb[uno].device);
					blobmsg_add_u64(b, "size", usb[uno].size);
					blobmsg_add_string(b, "mntdir", usb[uno].mount);
				}
			}
			blobmsg_close_table(b, t);
			uno++;
		}
		closedir(dir);
	} else {
		perror ("Could not open /sys/bus/usb/devices directory");
	}
}


static void
router_dump_ports(struct blob_buf *b, char *interface)
{
	void *t, *c, *h, *s;
	int pno, i, j;
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
		for (i = 1; strlen(port[i].name) > 2; i++) {
			if(strcmp(port[i].name, ports[pno]))
				continue;
			if(!strncmp(port[i].device, "wl", 2) && strlen(port[i].ssid) > 2)
				t = blobmsg_open_table(b, port[i].ssid);
			else
				t = blobmsg_open_table(b, port[i].name);
			blobmsg_add_string(b, "device", port[i].device);
			c = blobmsg_open_array(b, "hosts");
			for(j=0; port[i].client[j].exists; j++) {
				h = blobmsg_open_table(b, "NULL");
				blobmsg_add_string(b, "hostname", port[i].client[j].hostname);
				blobmsg_add_string(b, "ipaddr", port[i].client[j].ipaddr);
				blobmsg_add_string(b, "macaddr", port[i].client[j].macaddr);
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
network_dump_leases(struct blob_buf *b, char *leasenet)
{
	void *t;
	char leasenum[16];
	int i;

	for (i = 0; i < MAX_CLIENT; i++) {
		if (!clients[i].exists)
			break;
		if (clients[i].dhcp && !strcmp(clients[i].network, leasenet)) {
			sprintf(leasenum, "lease-%d", i + 1);
			t = blobmsg_open_table(b, leasenum);
			blobmsg_add_string(b, "leaseno", clients[i].leaseno);
			blobmsg_add_string(b, "hostname", clients[i].hostname);
			blobmsg_add_string(b, "ipaddr", clients[i].ipaddr);
			blobmsg_add_string(b, "macaddr", clients[i].macaddr);
			blobmsg_add_string(b, "device", clients[i].device);
			blobmsg_add_u8(b, "connected", clients[i].connected);
			blobmsg_close_table(b, t);
		}
	}
}

static void
host_dump_status(struct blob_buf *b, char *addr, bool byIP)
{
	int i;

	if(byIP) {
		for (i=0; clients[i].exists; i++)
			if(!strcmp(clients[i].ipaddr, addr)) {
				blobmsg_add_string(b, "hostname", clients[i].hostname);
				blobmsg_add_string(b, "macaddr", clients[i].macaddr);
				blobmsg_add_string(b, "network", clients[i].network);
				blobmsg_add_string(b, "device", clients[i].device);
				blobmsg_add_u8(b, "connected", clients[i].connected);
				blobmsg_add_u8(b, "wireless", clients[i].wireless);
				/*if(clients[i].connected)
					blobmsg_add_u32(b, "active_cons", sta_info.connum);*/
				if(clients[i].wireless) {
					blobmsg_add_string(b, "wdev", clients[i].wdev);
				}
				break;
			}
	}
	else {
		for (i=0; clients[i].exists; i++)
			if(!strcasecmp(clients[i].macaddr, addr)) {
				blobmsg_add_string(b, "hostname", clients[i].hostname);
				blobmsg_add_string(b, "ipaddr", clients[i].ipaddr);
				blobmsg_add_string(b, "network", clients[i].network);
				blobmsg_add_string(b, "device", clients[i].device);
				blobmsg_add_u8(b, "connected", clients[i].connected);
				blobmsg_add_u8(b, "wireless", clients[i].wireless);
				/*if(clients[i].connected)
					blobmsg_add_u32(b, "active_cons", sta_info.connum);*/
				if(clients[i].wireless) {
					blobmsg_add_string(b, "wdev", clients[i].wdev);
				}
				break;
			}
	}
}

/* ROUTER OBJECT */
static int
quest_router_specific(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[QUEST_NAME]) || (strcmp(blobmsg_data(tb[QUEST_NAME]), "system") && strcmp(blobmsg_data(tb[QUEST_NAME]), "memory")
		&& strcmp(blobmsg_data(tb[QUEST_NAME]), "keys") && strcmp(blobmsg_data(tb[QUEST_NAME]), "specs")))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&bb, 0);

	if (!strcmp(blobmsg_data(tb[QUEST_NAME]), "system"))
		router_dump_system_info(&bb, false);
	else if (!strcmp(blobmsg_data(tb[QUEST_NAME]), "memory"))
		router_dump_memory_info(&bb, false);
	else if (!strcmp(blobmsg_data(tb[QUEST_NAME]), "keys"))
		router_dump_keys(&bb, false);
	else if (!strcmp(blobmsg_data(tb[QUEST_NAME]), "specs"))
		router_dump_specs(&bb, false);

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_info(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	dump_sysinfo(&router, &memory);

	blob_buf_init(&bb, 0);
	router_dump_system_info(&bb, true);
	router_dump_memory_info(&bb, true);
	router_dump_keys(&bb, true);
	router_dump_specs(&bb, true);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_filesystem(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *a, *t;
	FILE *df;
	char line[128];
	char name[64];
	char mounted_on[128];
	char use_per[5];
	int blocks, used, available;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "filesystem");
	if ((df = popen("df", "r"))) {
		while(fgets(line, sizeof(line), df) != NULL)
		{
			remove_newline(line);
			single_space(line);
			if (sscanf(line, "%s %d %d %d %s %s", name, &blocks, &used, &available, use_per, mounted_on) == 6) {
				use_per[strlen(use_per)-1] = '\0';
				t = blobmsg_open_table(&bb, "");
				blobmsg_add_string(&bb, "name", name);
				blobmsg_add_u32(&bb, "1kblocks", blocks);
				blobmsg_add_u32(&bb, "used", used);
				blobmsg_add_u32(&bb, "available", available);
				blobmsg_add_u32(&bb, "use_pre", atoi(use_per));
				blobmsg_add_string(&bb, "mounted_on", mounted_on);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(df);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static int
quest_password_set(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	pid_t pid;
	int fd, fds[2];
	char *hash;
	struct spwd *sp;
	struct stat s;
	struct blob_attr *tb[__P_MAX];

	blobmsg_parse(password_policy, __P_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[P_USER] || !tb[P_PASSWORD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if(tb[P_CURPASSWORD])
	{
		if (!(sp = getspnam(blobmsg_data(tb[P_USER]))))
			return UBUS_STATUS_PERMISSION_DENIED;

		hash = crypt(blobmsg_data(tb[P_CURPASSWORD]), sp->sp_pwdp);

		if(strcmp(hash, sp->sp_pwdp))
			return UBUS_STATUS_PERMISSION_DENIED;
	} else
		return UBUS_STATUS_PERMISSION_DENIED;

	if (stat("/usr/bin/passwd", &s))
		return UBUS_STATUS_NOT_FOUND;

	if (!(s.st_mode & S_IXUSR))
		return UBUS_STATUS_PERMISSION_DENIED;

	if (pipe(fds))
		return errno_status();

	switch ((pid = fork()))
	{
	case -1:
		close(fds[0]);
		close(fds[1]);
		return errno_status();

	case 0:
		uloop_done();

		dup2(fds[0], 0);
		close(fds[0]);
		close(fds[1]);

		if ((fd = open("/dev/null", O_RDWR)) > -1)
		{
			dup2(fd, 1);
			dup2(fd, 2);
			close(fd);
		}

		chdir("/");

		if (execl("/usr/bin/passwd", "/usr/bin/passwd",
		          blobmsg_data(tb[P_USER]), NULL))
			return errno_status();

	default:
		close(fds[0]);

		write(fds[1], blobmsg_data(tb[P_PASSWORD]),
		              blobmsg_data_len(tb[P_PASSWORD]) - 1);
		write(fds[1], "\n", 1);

		usleep(100 * 1000);

		write(fds[1], blobmsg_data(tb[P_PASSWORD]),
		              blobmsg_data_len(tb[P_PASSWORD]) - 1);
		write(fds[1], "\n", 1);

		close(fds[1]);

		waitpid(pid, NULL, 0);

		return 0;
	}
}

static int
quest_router_logread(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *a, *t;
	FILE *log;
	char line[512];
	char dayofweek[8];
	char month[8];
	int dayofmonth;
	char hour[8];
	int year;
	char id[32];
	char source[32];
	char time[64];

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "logs");
	if ((log = popen("logread -l 400", "r"))) {
		while(fgets(line, sizeof(line), log) != NULL)
		{
			remove_newline(line);
			if (sscanf(line, "%s %s %d %s %d %s %s:", dayofweek, month, &dayofmonth, hour, &year, id, source)) {
				sprintf(time, "%s %s %d %s %d", dayofweek, month, dayofmonth, hour, year);
				source[strlen(source)-1] = '\0';
				t = blobmsg_open_table(&bb, "");
				blobmsg_add_string(&bb, "time", time);
				blobmsg_add_string(&bb, "id", id);
				blobmsg_add_string(&bb, "source", source);
				blobmsg_add_string(&bb, "message", line+(int)(strstr(line,source)-&line[0])+strlen(source)+2);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(log);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static int
quest_router_networks(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_networks(&bb);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_clients(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_clients(&bb, false);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_connected_clients(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_clients(&bb, true);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

#if IOPSYS_BROADCOM
static int
quest_router_wl(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__WL_MAX];
	char wldev[8];
	bool nthere = false;
	int i;

	blobmsg_parse(wl_policy, __WL_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[RADIO_NAME]) && !(tb[VIF_NAME]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[RADIO_NAME] && strchr(blobmsg_data(tb[RADIO_NAME]), '.'))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(wldev, '\0', sizeof(wldev));
	if (tb[VIF_NAME])
		strcpy(wldev, blobmsg_data(tb[VIF_NAME]));
	else
		strcpy(wldev, blobmsg_data(tb[RADIO_NAME]));

	for (i=0; wireless[i].device; i++)
		if(!strcmp(wireless[i].vif, wldev)) {
			nthere = true;
			break;
		}

	if (!(nthere))
		return UBUS_STATUS_INVALID_ARGUMENT;

	int isup;
	wl_get_isup(wldev, &isup);

	int band;
	wl_get_band(wldev, &band);

	char bssid[24];
	wl_get_bssid(wldev, bssid);

	int rate;
	wl_get_bitrate(wldev, &rate);

	int bandwidth, channel, noise;
	wl_get_bssinfo(wldev, &bandwidth, &channel, &noise);


	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "wldev", wldev);
	blobmsg_add_u32(&bb, "radio", isup);
	blobmsg_add_string(&bb, "bssid", bssid);
	blobmsg_add_u32(&bb, "frequency", (band==1)?5:2);
	blobmsg_add_u32(&bb, "channel", channel);
	blobmsg_add_u32(&bb, "bandwidth", bandwidth);
	blobmsg_add_u32(&bb, "noise", noise);
	blobmsg_add_u32(&bb, "rate", rate);

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}
#endif

static int
quest_router_connected_clients6(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_clients6(&bb, true);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_igmp_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	IGMPTable table[MAX_IGMP_ENTRY];
	FILE *snptable;
	char line[256];
	int idx = 0;
	void *t, *a;

	if ((snptable = fopen("/proc/net/igmp_snooping", "r"))) {
		while(fgets(line, sizeof(line), snptable) != NULL)
		{
			remove_newline(line);
			table[idx].exists = false;
			if(sscanf(single_space(line),"%s %s %s %s %x %x %s %s %s %s %s %d %x %d",
					table[idx].bridge, table[idx].device, table[idx].srcdev, table[idx].tags, &(table[idx].lantci), &(table[idx].wantci),
					table[idx].group, table[idx].mode, table[idx].RxGroup, table[idx].source, table[idx].reporter,
					&(table[idx].timeout), &(table[idx].Index), &(table[idx].ExcludPt)) == 14)
			{
				table[idx].exists = true;
				idx++;
			}
		}
		fclose(snptable);
	} else
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "table");
	for (idx = 0; idx < MAX_IGMP_ENTRY; idx++) {
		if (!table[idx].exists)
			break;
		t = blobmsg_open_table(&bb, NULL);
		blobmsg_add_string(&bb,"bridge", table[idx].bridge);
		blobmsg_add_string(&bb,"device", table[idx].device);
		blobmsg_add_string(&bb,"srcdev", table[idx].srcdev);
		blobmsg_add_string(&bb,"tags", table[idx].tags);
		blobmsg_add_u32(&bb,"lantci", table[idx].lantci);
		blobmsg_add_u32(&bb,"wantci", table[idx].wantci);
		blobmsg_add_string(&bb,"group", table[idx].group);
		blobmsg_add_string(&bb,"mode", table[idx].mode);
		blobmsg_add_string(&bb,"rxgroup", table[idx].RxGroup);
		blobmsg_add_string(&bb,"source", table[idx].source);
		blobmsg_add_string(&bb,"reporter", table[idx].reporter);
		blobmsg_add_u32(&bb,"timeout", table[idx].timeout);
		blobmsg_add_u32(&bb,"index", table[idx].Index);
		blobmsg_add_u32(&bb,"excludpt", table[idx].ExcludPt);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_clients6(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_clients6(&bb, false);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_stas(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_stas(&bb, NULL, false);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_wireless_stas(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__WL_MAX];
	char lookup[8];
	bool nthere = false;
	int i;

	blobmsg_parse(wl_policy, __WL_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[RADIO_NAME]) && !(tb[VIF_NAME]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[RADIO_NAME] && strchr(blobmsg_data(tb[RADIO_NAME]), '.'))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(lookup, '\0', sizeof(lookup));
	if (tb[VIF_NAME])
		strcpy(lookup, blobmsg_data(tb[VIF_NAME]));
	else
		strcpy(lookup, blobmsg_data(tb[RADIO_NAME]));

	for (i=0; wireless[i].device; i++)
		if(!strcmp(wireless[i].vif, lookup)) {
			nthere = true;
			break;
		}

	if (!(nthere))
		return UBUS_STATUS_INVALID_ARGUMENT;


	blob_buf_init(&bb, 0);
	if (tb[RADIO_NAME])
		router_dump_stas(&bb, blobmsg_data(tb[RADIO_NAME]), false);
	else
		router_dump_stas(&bb, blobmsg_data(tb[VIF_NAME]), true);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_usbs(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__QUEST_MAX];

	blobmsg_parse(quest_policy, __QUEST_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	router_dump_usbs(&bb);
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

	blobmsg_parse(network_policy, __NETWORK_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[NETWORK_NAME]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	for (i=0; network[i].is_lan; i++)
		if(!strcmp(network[i].name, blobmsg_data(tb[NETWORK_NAME])))
			nthere = true;

	if (!(nthere))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&bb, 0);
	network_dump_leases(&bb, blobmsg_data(tb[NETWORK_NAME]));
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
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
		
	for (i=0; network[i].exists; i++) {
		if(!strcmp(network[i].name, blobmsg_data(tb[NETWORK_NAME])))
			if(!strcmp(network[i].type, "bridge")) {
			nthere = true;
			break;
		}
	}

	if (!(nthere))
		return UBUS_STATUS_INVALID_ARGUMENT;
	
	blob_buf_init(&bb, 0);
	router_dump_ports(&bb, blobmsg_data(tb[NETWORK_NAME]));
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}



static int
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

#if IOPSYS_BROADCOM
static int
quest_router_radios(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *t, *c;
	int i, j;
	int isup, band, rate, bw, channel, noise;
	char bitrate[10];
	char frequency[10];
	char bandwidth[10];

	blob_buf_init(&bb, 0);

	for (i = 0; i < MAX_RADIO; i++) {
		if (!radio[i].name)
			break;

		wl_get_isup(radio[i].name, &isup);

		wl_get_band(radio[i].name, &band);
		sprintf(frequency, "%sGHz", (band==1)?"5":"2.4");

		wl_get_bitrate(radio[i].name, &rate);
		sprintf(bitrate, "%d%s Mbps", (rate / 2), (rate & 1) ? ".5" : "");

		wl_get_bssinfo(radio[i].name, &bw, &channel, &noise);
		sprintf(bandwidth, "%dMHz", bw);

		t = blobmsg_open_table(&bb, radio[i].name);
		blobmsg_add_u8(&bb, "isup", isup);
		blobmsg_add_string(&bb, "frequency", frequency);
		blobmsg_add_string(&bb, "bandwidth", bandwidth);
		blobmsg_add_u32(&bb, "channel", channel);
		blobmsg_add_u32(&bb, "noise", noise);
		blobmsg_add_string(&bb, "rate", bitrate);
		c = blobmsg_open_array(&bb, "hwmodes");
		for(j=0; radio[i].hwmodes[j]; j++) {
			blobmsg_add_string(&bb, "", radio[i].hwmodes[j]);
		}
		blobmsg_close_array(&bb, c);
		c = blobmsg_open_array(&bb, "bwcaps");
		for(j=0; radio[i].bwcaps[j]; j++) {
			blobmsg_add_u32(&bb, "", radio[i].bwcaps[j]);
		}
		blobmsg_close_array(&bb, c);
		c = blobmsg_open_array(&bb, "channels");
		for(j=0; radio[i].channels[j] != 0; j++) {
			blobmsg_add_u32(&bb, "", radio[i].channels[j]);
		}
		blobmsg_close_array(&bb, c);
		blobmsg_close_table(&bb, t);
	}

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}
#endif

static int
quest_reload(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	pthread_mutex_lock(&lock);
	dump_hostname(&router);
	load_networks();
#if IOPSYS_BROADCOM
	load_wireless();
#endif
	pthread_mutex_unlock(&lock);
	return 0;
}

static struct ubus_method router_object_methods[] = {
	UBUS_METHOD_NOARG("info", quest_router_info),
	UBUS_METHOD_NOARG("filesystem", quest_router_filesystem),
	UBUS_METHOD("quest", quest_router_specific, quest_policy),
	UBUS_METHOD_NOARG("logs", quest_router_logread),
	UBUS_METHOD_NOARG("networks", quest_router_networks),
#if IOPSYS_BROADCOM
	UBUS_METHOD("wl", quest_router_wl, wl_policy),
#endif
	UBUS_METHOD_NOARG("dslstats", dslstats_rpc), 
	UBUS_METHOD_NOARG("clients", quest_router_clients),
	UBUS_METHOD_NOARG("clients6", quest_router_clients6),
	UBUS_METHOD_NOARG("connected", quest_router_connected_clients),
	UBUS_METHOD_NOARG("connected6", quest_router_connected_clients6),
	UBUS_METHOD_NOARG("igmptable", quest_router_igmp_table),
	UBUS_METHOD("sta", quest_router_wireless_stas, wl_policy),
	UBUS_METHOD_NOARG("stas", quest_router_stas),
	UBUS_METHOD("ports", quest_router_ports, network_policy),
	UBUS_METHOD("leases", quest_network_leases, network_policy),
	UBUS_METHOD("host", quest_host_status, host_policy),
	UBUS_METHOD_NOARG("usb", quest_router_usbs),
#if IOPSYS_BROADCOM
	UBUS_METHOD_NOARG("radios", quest_router_radios),
#endif
	UBUS_METHOD("password_set", quest_password_set, password_policy),
	UBUS_METHOD_NOARG("reload", quest_reload),
};

static struct ubus_object_type router_object_type =
	UBUS_OBJECT_TYPE("system", router_object_methods);

static struct ubus_object router_object = {
	.name = "router",
	.type = &router_object_type,
	.methods = router_object_methods,
	.n_methods = ARRAY_SIZE(router_object_methods),
};
/* END OF ROUTER OBJECT */

#if IOPSYS_BROADCOM
/* WPS OBJECT */
static int
wps_status(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	char status[16];
	int code = atoi(chrCmd("nvram get wps_proc_status"));

	switch (code) {
		case 0:
			strcpy(status, "init");
			break;
		case 1:
			strcpy(status, "processing");
			break;
		case 2:
			strcpy(status, "success");
			break;
		case 3:
			strcpy(status, "fail");
			break;
		case 4:
			strcpy(status, "timeout");
			break;
		case 7:
			strcpy(status, "msgdone");
			break;
		default:
			strcpy(status, "unknown");
			break;
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "code", code);
	blobmsg_add_string(&bb, "status", status);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
wps_pbc(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	system("killall -SIGUSR2 wps_monitor");
	return 0;
}

static int
wps_pbc_client(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	system("INTERFACE=wpscbutton ACTION=register /sbin/hotplug-call button &");
	return 0;
}

static int
wps_genpin(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *genpin;
	char cmnd[16];
	char pin[9] = { '\0' };

	sprintf(cmnd, "wps_cmd genpin");
	if ((genpin = popen(cmnd, "r"))) {
		fgets(pin, sizeof(pin), genpin);
		remove_newline(pin);
		pclose(genpin);
	}

	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "pin", pin);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
wps_checkpin(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__PIN_MAX];

	blobmsg_parse(pin_policy, __PIN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[PIN]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	FILE *checkpin;
	char cmnd[32];
	char pin[9] = { '\0' };
	bool valid = false;

	snprintf(cmnd, 32, "wps_cmd checkpin %s", (char*)blobmsg_data(tb[PIN]));
	if ((checkpin = popen(cmnd, "r"))) {
		fgets(pin, sizeof(pin), checkpin);
		remove_newline(pin);
		pclose(checkpin);
	}

	if(strlen(pin))
		valid = true;

	blob_buf_init(&bb, 0);
	blobmsg_add_u8(&bb, "valid", valid);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
wps_stapin(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__PIN_MAX];

	blobmsg_parse(pin_policy, __PIN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[PIN]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	runCmd("wps_cmd addenrollee wl0 sta_pin=%s &", blobmsg_data(tb[PIN]));

	return 0;
}

static int
wps_setpin(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__PIN_MAX];

	blobmsg_parse(pin_policy, __PIN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[PIN]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	runCmd("wps_cmd setpin %s &", blobmsg_data(tb[PIN]));

	return 0;
}

static int
wps_showpin(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *showpin;
	char cmnd[32];
	char pin[9] = { '\0' };

	sprintf(cmnd, "nvram get wps_device_pin");
	if ((showpin = popen(cmnd, "r"))) {
		fgets(pin, sizeof(pin), showpin);
		remove_newline(pin);
		pclose(showpin);
	}

	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "pin", pin);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
wps_stop(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	system("killall -SIGTERM wps_monitor");
	system("nvram set wps_proc_status=0");
	system("wps_monitor &");
	return 0;
}


static struct ubus_method wps_object_methods[] = {
	UBUS_METHOD_NOARG("status", wps_status),
	UBUS_METHOD_NOARG("pbc", wps_pbc),
	UBUS_METHOD_NOARG("pbc_client", wps_pbc_client),
	UBUS_METHOD_NOARG("genpin", wps_genpin),
	UBUS_METHOD("checkpin", wps_checkpin, pin_policy),
	UBUS_METHOD("stapin", wps_stapin, pin_policy),
	UBUS_METHOD("setpin", wps_setpin, pin_policy),
	UBUS_METHOD_NOARG("showpin", wps_showpin),
	UBUS_METHOD_NOARG("stop", wps_stop),
};

static struct ubus_object_type wps_object_type =
	UBUS_OBJECT_TYPE("wps", wps_object_methods);

static struct ubus_object wps_object = {
	.name = "wps",
	.type = &wps_object_type,
	.methods = wps_object_methods,
	.n_methods = ARRAY_SIZE(wps_object_methods),
};

/* END OF WPS OBJECT */
#endif /* IOPSYS_BROADCOM */

static void
quest_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	system_fd_set_cloexec(ctx->sock.fd);
}

static void
quest_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = quest_ubus_reconnect_timer,
	};
	int t = 2;

	if (ubus_reconnect(ctx, ubus_path) != 0) {
		printf("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	printf("reconnected to ubus, new id: %08x\n", ctx->local_id);
	quest_ubus_add_fd();
}



static void
quest_ubus_connection_lost(struct ubus_context *ctx)
{
	quest_ubus_reconnect_timer(NULL);
}

static void
quest_add_object(struct ubus_object *obj)
{
	int ret = ubus_add_object(ctx, obj);

	if (ret != 0)
		fprintf(stderr, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
}

static int
quest_ubus_init(const char *path)
{
	uloop_init();
	ubus_path = path;

	ctx = ubus_connect(path);
	if (!ctx)
		return -EIO;

	printf("connected as %08x\n", ctx->local_id);
	ctx->connection_lost = quest_ubus_connection_lost;
	quest_ubus_add_fd();

	quest_add_object(&router_object);
#if IOPSYS_BROADCOM
	quest_add_object(&wps_object);
#endif

	return 0;
}

void *dump_router_info(void *arg)
{
	int lpcnt = 0;

	jiffy_counts_t cur_jif = {0}, prev_jif = {0};
	
	init_db_hw_config();
	load_networks();
#if IOPSYS_BROADCOM
	load_wireless();
#endif
	dump_keys(&keys);
	dump_specs(&spec);
	dump_static_router_info(&router);
	dump_hostname(&router);
	while (true) {
		pthread_mutex_lock(&lock);
		dump_cpuinfo(&router, &prev_jif, &cur_jif);
		populate_clients();
		pthread_mutex_unlock(&lock);
		get_jif_val(&prev_jif);
		usleep(sleep_time);
		recalc_sleep_time(false, 0);
		get_jif_val(&cur_jif);
		lpcnt++;
		if (lpcnt == 20) {
			lpcnt = 0;
			memset(clients, '\0', sizeof(clients));
			memset(clients6, '\0', sizeof(clients6));
		}
	}

	return NULL;
}

int main(int argc, char **argv)
{
	const char *path = NULL;
	int pt;

	if(argc > 1 && argv[1] && strlen(argv[1]) > 0){
		path = argv[1]; 
	}

	if (quest_ubus_init(path) < 0) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return 1;
	}

	if (pthread_mutex_init(&lock, NULL) != 0)
	{
		fprintf(stderr, "Failed to initialize mutex\n");
		return 1;
	}
	
	if ((pt = pthread_create(&(tid[0]), NULL, &dump_router_info, NULL) != 0)) {
		fprintf(stderr, "Failed to create thread\n");
		return 1;
	}

	uloop_run();
	pthread_mutex_destroy(&lock);
	ubus_free(ctx);	

	return 0;
}

