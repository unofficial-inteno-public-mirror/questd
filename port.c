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

#include <libubox/blobmsg.h>
#include <libubus.h>

#include "network.h"
#include "port.h"
#include "tools.h"

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

#if IOPSYS_BROADCOM
	sprintf(cmnd, ". /lib/network/config.sh && interfacename %s 2>/dev/null", port->device);
	if (!(in = popen(cmnd, "r")))
		exit(1);

	fgets(buf, sizeof(buf), in);
	pclose(in);
	remove_newline(buf);
	strcpy(port->name, buf);

	memset(cmnd, '\0', sizeof(cmnd));
	memset(buf, '\0', sizeof(buf));

	if(!strncmp(port->device, "wl", 2)) {
		sprintf(cmnd, "wlctl -i %s ssid | awk '{print$3}' | sed 's/\"//g' 2>/dev/null", port->device);
		if (!(in = popen(cmnd, "r")))
			exit(1);

		fgets(buf, sizeof(buf), in);
		pclose(in);
		remove_newline(buf);
		strcpy(port->ssid, buf);
	}
#else IOPSYS_MEDIATEK
	if(!strncmp(port->device, "ra", 2)) {
		sprintf(cmnd, "iwinfo %s info 2>/dev/null| grep ESSID | awk '{print$NF}' | tr -d '\"'", port->device);
		if (!(in = popen(cmnd, "r")))
			exit(1);

		fgets(buf, sizeof(buf), in);
		pclose(in);
		remove_newline(buf);
		strcpy(port->ssid, buf);
		strcpy(port->name, "WLAN");
	} else if (!strncmp(port->device, "eth", 3))
		strcpy(port->name, "LAN");
#endif
}

int
get_port_speed(char *linkspeed, char *device)
{
#if IOPSYS_BROADCOM
	const char *portspeed, *issfp;
	char duplex[16] = {0};
	char ad[8] = {0};
	int speed = 0, fixed = 0;
	char output[512] = {0};

	issfp = chrCmd(output, 512, "ethctl %s media-type 2>&1| grep sfp", device);

	if (!strlen(issfp)) {
		portspeed = chrCmd(output, 512, "ethctl %s media-type 2>/dev/null | sed -n '2p'", device);

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
		portspeed = chrCmd(output, 512, "ethctl %s media-type sfp fiber 2>&1 | tr '\n' '|' | grep 'Link is up' | tr '|' '\n' | sed -n '1p'", device);

		if (!strlen(portspeed))
			portspeed = chrCmd(output, 512, "ethctl %s media-type sfp copper 2>&1 | tr '\n' '|' | grep 'Link is up' | tr '|' '\n' | sed -n '1p'", device);

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
	portspeed = chrCmd(output, 512, "ethctl %s media-type 2>&1 | sed -n '4p'", device);

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
	strcpy(linkspeed, "Auto-negotiated 1000 Mbps Full Duplex");
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

#if IOPSYS_BROADCOM
	sprintf(cmnd, "brctl showbr %s | awk '{print$NF}' | grep -v interfaces | tr '\n' ' '", bridge);
#else
	sprintf(cmnd, "brctl show %s | awk '{print$NF}' | grep -v interfaces | tr '\n' ' '", bridge);
#endif

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

static int
quest_portinfo(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	char linkspeed[64] = {0};
	struct blob_attr *tb[__PORT_MAX];
	int ret;

	blobmsg_parse(port_policy, __PORT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[PORT])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ret = get_port_speed(linkspeed, (char*)blobmsg_data(tb[PORT]));
	if(ret >= 0){
		blob_buf_init(&bb, 0);
		blobmsg_add_string(&bb, "type", (ret)?"SFP":"Ethernet");
		blobmsg_add_string(&bb, "speed", linkspeed);
		ubus_send_reply(ctx, req, bb.head);
		return 0;
	}
	return UBUS_STATUS_INVALID_ARGUMENT;
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
