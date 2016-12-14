/*
 * port -- provides router.port object of questd
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

#include <stdlib.h>

#include <linux/if_bridge.h>

#if IOPSYS_MEDIATEK
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
//#include <linux/switch.h>
#include <swlib.h>
#endif


#include <libubox/blobmsg.h>
#include <libubus.h>
#include <stdbool.h>
#include <dirent.h>

#include "network.h"
#include "port.h"
#include "tools.h"

#define MAX_DEVS	50

enum number_or_direction{
	PORT_TYPE_DIRECTION,
	PORT_TYPE_NUMBER,
};
// this comes from linux/switch.h that can not be included at the same time as linux/if_bridge.h
/* data types */
enum switch_val_type {
	SWITCH_TYPE_UNSPEC,
	SWITCH_TYPE_INT,
	SWITCH_TYPE_STRING,
	SWITCH_TYPE_PORTS,
	SWITCH_TYPE_LINK,
	SWITCH_TYPE_NOVAL,
};

enum {
	PORT,
	__PORT_MAX
};

static const struct blobmsg_policy port_policy[__PORT_MAX] = {
	[PORT] =	{ .name = "port",	.type = BLOBMSG_TYPE_STRING }
};

static struct blob_buf bb;

static long
get_port_stat(char *dev, char *stat)
{
	FILE *in;
	char cmnd[64];
	char result[32];

	sprintf(cmnd, "/sys/class/net/%s/statistics/%s", dev, stat);
	if ((in = fopen(cmnd, "r"))) {
		fgets(result, sizeof(result), in);
		fclose(in);
	}

	return atoi(result);
}

void
get_port_stats(Port *port)
{
	port->stat.rx_bytes = get_port_stat(port->device, "rx_bytes");
	port->stat.rx_packets = get_port_stat(port->device, "rx_packets");
	port->stat.rx_errors = get_port_stat(port->device, "rx_errors");
	port->stat.tx_bytes = get_port_stat(port->device, "tx_bytes");
	port->stat.tx_packets =get_port_stat(port->device, "tx_packets");
	port->stat.tx_errors = get_port_stat(port->device, "tx_errors");
}

void
get_port_name(Port *port)
{
	FILE *in;
	char buf[32];
	char cmnd[80];

	sprintf(cmnd, ". /lib/network/config.sh && interfacename %s 2>/dev/null", port->device);
	if (!(in = popen(cmnd, "r")))
		exit(1);

	fgets(buf, sizeof(buf), in);
	pclose(in);
	remove_newline(buf);
	strcpy(port->name, buf);

	memset(cmnd, '\0', sizeof(cmnd));
	memset(buf, '\0', sizeof(buf));

#if IOPSYS_BROADCOM
	if(!strncmp(port->device, "wl", 2)) {
		sprintf(cmnd, "wlctl -i %s ssid | awk '{print$3}' | sed 's/\"//g' 2>/dev/null", port->device);
#elif IOPSYS_MEDIATEK
	if(!strncmp(port->device, "ra", 2)) {
		sprintf(cmnd, "iwinfo %s info 2>/dev/null| grep ESSID | awk '{print$NF}' | tr -d '\"'", port->device);
#endif
		if (!(in = popen(cmnd, "r")))
			exit(1);

		fgets(buf, sizeof(buf), in);
		pclose(in);
		remove_newline(buf);
		strcpy(port->ssid, buf);
	}
}

int
get_switch_port_data(const char *device, enum number_or_direction type)
{
	int scaned_chars, num_ports, port_number, port_offset, dev_offset;
	char *s_num_ports = NULL, *devices = NULL, *ports = NULL, *endptr;
	char dev[16], port[16];
	float dummy;

	scaned_chars = sscanf(device, "eth%f", &dummy);
	if(scaned_chars != 1)
		return -1;

	get_db_value("ethernetPorts", &s_num_ports);
	get_db_value("ethernetPortOrder", &devices);
	get_db_value(type == PORT_TYPE_NUMBER ? "ethernetSwitchPortOrder" : "ethernetPortNames", &ports);
	if(!s_num_ports || !*s_num_ports || !devices || !*devices || !ports || !*ports)
		return -1;
	if((num_ports = atoi(s_num_ports)) < 1)
		return -1;

	bool found = false;
	while(num_ports > 0 && sscanf(devices, "%s%n", dev, &dev_offset) > 0 &&
			sscanf(ports, "%s%n", port, &port_offset) > 0){
		if(strncmp(dev, device, strlen(device)) == 0){
			found = true;
			break;
		}
		if(strlen(devices) < dev_offset || strlen(ports) < port_offset)
			break;
		devices += dev_offset;
		ports += port_offset;
		num_ports --;
	}
	if(!found)
		return -1;
	if(type == PORT_TYPE_NUMBER){
		port_number = strtol(port, &endptr, 10);
		if(*endptr)
			return -1;
		return port_number;
	}else{
		if(strncmp(port, "LAN", 3) == 0)
			return 0;
		else if(strncmp(port, "WAN", 3) == 0)
			return 1;
		else
			return -1;
	}
}

int
get_port_speed(char *linkspeed, char *device)
{
#if IOPSYS_BROADCOM
	const char *portspeed, *issfp;
	char duplex[16];
	char ad[8];
	int speed, fixed;

	issfp = chrCmd("ethctl %s media-type 2>&1| grep sfp", device);

	if (!strlen(issfp)) {
		portspeed = chrCmd("ethctl %s media-type 2>/dev/null | sed -n '2p'", device);

		if (!strlen(portspeed))
			return -1;

		if (sscanf(portspeed, "The autonegotiated media type is %dBT %s Duplex", &speed, duplex))
			fixed = 0;
		else if (sscanf(portspeed, "The autonegotiated media type is %dbase%s.", &speed, duplex))
			fixed = 0;
		else if (sscanf(portspeed, " Speed fixed at %dMbps, %s-duplex.", &speed, duplex))
			fixed = 1;

		if (strcmp(portspeed, "Link is down") == 0){
			strcpy(linkspeed, "Auto");
		}else{
			if (strstr(duplex, "ull") || strstr(portspeed, "FD"))
				strcpy(duplex, "Full");
			else
				strcpy(duplex, "Half");
			sprintf(linkspeed, "%s %d Mbps %s Duplex", (fixed)?"Fixed":"Auto-negotiated", speed, duplex);
		}

		return 0;
	} else {
		portspeed = chrCmd("ethctl %s media-type sfp fiber 2>&1 | tr '\n' '|' | grep 'Link is up' | tr '|' '\n' | sed -n '1p'", device);

		if (!strlen(portspeed))
			portspeed = chrCmd("ethctl %s media-type sfp copper 2>&1 | tr '\n' '|' | grep 'Link is up' | tr '|' '\n' | sed -n '1p'", device);

		if (!strlen(portspeed))
			return -1;

		if(!strcmp(portspeed, "Auto-negotiation enabled."))
			goto eth;

		if (sscanf(portspeed, "Auto Detection %s Media type is %dFD", ad, &speed))
			strcpy(duplex, "Full");
		else if (sscanf(portspeed, "Auto Detection %s Media type is %dHD", ad, &speed))
			strcpy(duplex, "Half");

		sprintf(linkspeed, "%s %d Mbps %s Duplex", (strstr(ad, "off"))?"Fixed":"Auto-negotiated", speed, duplex);

		if(speed)
			return 1;
	}

eth:
	portspeed = chrCmd("ethctl %s media-type 2>&1 | sed -n '4p'", device);

	if (!strlen(portspeed))
		return -1;

	if (sscanf(portspeed, "The autonegotiated media type is %dBT %s Duplex", &speed, duplex))
		fixed = 0;
	else if (sscanf(portspeed, "The autonegotiated media type is %dbase%s.", &speed, duplex))
		fixed = 0;
	else if (sscanf(portspeed, " Speed fixed at %dMbps, %s-duplex.", &speed, duplex))
		fixed = 1;

	if (strcmp(portspeed, "Link is down") == 0){
		strcpy(linkspeed, "Auto");
	}else{
		if (strstr(duplex, "ull") || strstr(portspeed, "FD"))
			strcpy(duplex, "Full");
		else
			strcpy(duplex, "Half");
		sprintf(linkspeed, "%s %d Mbps %s Duplex", (fixed)?"Fixed":"Auto-negotiated", speed, duplex);
	}

	return 0;
#else
	struct switch_dev *sw_dev;
	struct switch_attr *attr;
	struct switch_val val;
	struct switch_port_link *link;

	int port_number = get_switch_port_data(device, PORT_TYPE_NUMBER);
	if(port_number == -1)
		return -1;

	sw_dev = swlib_connect("switch0");
	if(!sw_dev) return -1;
	swlib_scan(sw_dev);

	val.port_vlan = port_number;
	attr = swlib_lookup_attr(sw_dev, SWLIB_ATTR_GROUP_PORT, "link");
	if(attr->type != SWITCH_TYPE_LINK)
		return -1;
	swlib_get_attr(sw_dev, attr, &val);
	link = val.value.link;
	if(link->link)
		sprintf(linkspeed, "%s %d Mbps %s Duplex", link->aneg ? "Auto-negotiated" : "Fixed",
				link->speed, link->duplex ? "Full" : "Half");
	else
		sprintf(linkspeed, "Link is down");
	swlib_free_all(sw_dev);
	return 0;
#endif
}

void
get_bridge_ports(char *bridge, char **ports)
{
	FILE *in;
	char buf[64];
	char cmnd[128];
	
	*ports = "";

	sprintf(cmnd, "brctl showbr %s | awk 'NR>1 {printf \"%%s \", $NF}'", bridge);

	if (!(in = popen(cmnd, "r")))
		exit(1);

	fgets(buf, sizeof(buf), in);
	pclose(in);
	*ports = strdup(buf);
}

static int
compare_fdbs(const void *_f0, const void *_f1)
{
	const struct fdb_entry *f0 = _f0;
	const struct fdb_entry *f1 = _f1;

	return memcmp(f0->mac_addr, f1->mac_addr, 6);
}

static inline void
copy_fdb(struct fdb_entry *ent, const struct __fdb_entry *f)
{
	memcpy(ent->mac_addr, f->mac_addr, 6);
	ent->port_no = f->port_no;
	ent->is_local = f->is_local;
}

static int
bridge_read_fdb(const char *bridge, struct fdb_entry *fdbs, unsigned long offset, int num)
{
	FILE *f;
	int i, n;
	struct __fdb_entry fe[num];
	char path[256];
	
	snprintf(path, 256, "/sys/class/net/%s/brforward", bridge);
	f = fopen(path, "r");
	if (f) {
		fseek(f, offset*sizeof(struct __fdb_entry), SEEK_SET);
		n = fread(fe, sizeof(struct __fdb_entry), num, f);
		fclose(f);
	}

	for (i = 0; i < n; i++) 
		copy_fdb(fdbs+i, fe+i);

	return n;
}

char*
get_clients_onport(char *bridge, int portno)
{
	int i, n;
	struct fdb_entry *fdb = NULL;
	int offset = 0;
	static char tmpmac[2400];
	char mac[24];

	memset(tmpmac, '\0', 2400);

	for(;;) {
		fdb = realloc(fdb, (offset + CHUNK) * sizeof(struct fdb_entry));
		if (!fdb) {
			fprintf(stderr, "Out of memory\n");
			return "";
		}
			
		n = bridge_read_fdb(bridge, fdb+offset, offset, CHUNK);
		if (n == 0)
			break;

		if (n < 0) {
			fprintf(stderr, "read of forward table failed: %s\n",
				strerror(errno));

			free(fdb);
			return "";
		}

		offset += n;
	}

	qsort(fdb, offset, sizeof(struct fdb_entry), compare_fdbs);

	for (i = 0; i < offset; i++) {
		const struct fdb_entry *f = fdb + i;
		if (f->port_no == portno && !f->is_local) {
			sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", f->mac_addr[0], f->mac_addr[1], f->mac_addr[2], f->mac_addr[3], f->mac_addr[4], f->mac_addr[5]);
			strcat(tmpmac, " ");
			strcat(tmpmac, mac);
		}
	}

	free(fdb);

	return tmpmac;
}

bool valid_port(char *name, char **list, int num){
	const char *exclude[] = {".", "..", "bcmsw", "dsl", "gre", "ifb", "ip6tnl", "lo", "sit", "siit", "br-"};
	int len = sizeof(exclude)/sizeof(char *);
	int i;
	for(i = 0; i < num; i++){
		if(strcmp(name, list[i]) == 0)
			return false;
	}
	for(i = 0; i < len; i++){
		if(strncmp(name, exclude[i], strlen(exclude[i])) == 0)
			return false;
	}
	return true;
}

const char*
get_port_type(char *port){
	if(strncmp(port, "eth", 3) == 0){
		char dummy[64];
		int p = get_port_speed(port,dummy);
		switch(p){
		case 1:
			return "SFP";
		case 0:
			return "Ethernet";
		}
		return "Unknown";
	}
	else if(strncmp(port, "atm", 3) == 0)
		return "ADSL";
	else if(strncmp(port, "ptm", 3) == 0)
		return "VDSL";
	else if(strncmp(port, "wl", 2) == 0 || strncmp(port, "ra", 2) == 0 || strncmp(port, "apcli", 5) == 0)
		return "Wireless";
	else if(strncmp(port, "wwan", 4) == 0)
		return "Mobile";
	else if(strncmp(port, "br-", 3) == 0)
		return "Bridge";
	else
		return "Unknown";
}

const char*
get_port_direction(char *port){
#if IOPSYS_BROADCOM
	char linkspeed[64] = {0};
	if((strncmp(port, "eth", 3) == 0 && strlen(port) > 4) || get_port_speed(linkspeed, port) < 0)
		return "Up"
#elif IOPSYS_MEDIATEK
	if(strncmp(port, "eth", 3) == 0){
		int dir = get_switch_port_data(port, PORT_TYPE_DIRECTION);
		if(dir == 1)
			return "Up";
		else if(dir == 0)
			return "Down";
		else
			return "Unknown";
	}
#endif
	if(strncmp(port, "asl", 3) == 0 || strncmp(port, "ptm", 3) == 0 || strncmp(port, "wwan", 4) == 0 || strncmp(port, "apcli", 5) == 0)
		return "Up";
	return "Down";
}

bool
has_port_speed(char *port, char *speed){
	if(strncmp(port, "eth", 3) == 0 && strlen(port) == 4){
		get_port_speed(speed, port);
		return true;
	}else if(strncmp(port, "eth", 3) == 0){
#if IOPSYS_BROADCOM
		char p[5];
		strncpy(p, port, 4);
		p[4] = '\0';
		get_port_speed(speed, p);
#elif IOPSYS_MEDIATEK
		get_port_speed(speed, port);
#endif
		return true;
	}
	return false;
}

static int
quest_portinfo(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	char linkspeed[64] = {0};
	char *invalid_eth_devs[MAX_DEVS];
	struct blob_attr *tb[__PORT_MAX];
	int ret, num_eth = 0,len;
	DIR *dir;
	void *t;
	struct dirent *ent;

	blobmsg_parse(port_policy, __PORT_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[PORT]){
		blob_buf_init(&bb, 0);
		blobmsg_add_string(&bb, "type", get_port_type((char *)blobmsg_data(tb[PORT])));
		blobmsg_add_string(&bb, "direction", get_port_direction((char *)blobmsg_data(tb[PORT])));
		if(has_port_speed(linkspeed, (char*)blobmsg_data(tb[PORT])))
			blobmsg_add_string(&bb, "speed", linkspeed);
		ubus_send_reply(ctx, req, bb.head);
		return UBUS_STATUS_OK;
	}

	char *dot;
	// no port specified. Dump all ports
	dir = opendir("/sys/class/net");
	if(!dir){
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	while((ent = readdir(dir)) != NULL){
		if(strncmp(ent->d_name, "eth", 3) != 0)
			continue;
		dot = strchr(ent->d_name, '.');
		if(!dot)
			continue;

		if(num_eth >= MAX_DEVS)
			break;
		len = (dot - ent->d_name)/sizeof(char);
		invalid_eth_devs[num_eth] = strndup(ent->d_name, len);
		if(!invalid_eth_devs[num_eth])
			break;
		num_eth++;
	}

	rewinddir(dir);
	blob_buf_init(&bb, 0);
	while((ent = readdir(dir)) != NULL){
		if(!valid_port(ent->d_name, invalid_eth_devs, num_eth))
			continue;
		t = blobmsg_open_table(&bb, ent->d_name);
		blobmsg_add_string(&bb, "type", get_port_type(ent->d_name));
		blobmsg_add_string(&bb, "direction", get_port_direction(ent->d_name));
		if(has_port_speed(ent->d_name, linkspeed))
			blobmsg_add_string(&bb, "speed", linkspeed);
		blobmsg_close_table(&bb, t);
	}

	ubus_send_reply(ctx, req, bb.head);
	for(ret = 0; ret < num_eth; ret++){
		if(ret == MAX_DEVS) break;
		free(invalid_eth_devs[ret]);
	}
	return UBUS_STATUS_OK;
}

struct ubus_method port_object_methods[] = {
	UBUS_METHOD("status", quest_portinfo, port_policy),
};

struct ubus_object_type port_object_type =
	UBUS_OBJECT_TYPE("port", port_object_methods);

struct ubus_object port_object = {
	.name = "router.port",
	.type = &port_object_type,
	.methods = port_object_methods,
	.n_methods = ARRAY_SIZE(port_object_methods),
};
