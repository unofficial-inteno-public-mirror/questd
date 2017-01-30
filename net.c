/*
 * net -- provides router.net object of questd
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

#include "tools.h"
#include "net.h"
#include "questd.h"

#define MAX_IFACES 32

static struct blob_buf bb;

int
arp_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *arptable;
	void *t, *a;
	char line[512];
	char ipaddr[24];
	char macaddr[24];
	char device [16];
	char mask[8];
	char hw[8];
	char flag[8];
	char tmp[16];

	if ((arptable = fopen("/proc/net/arp", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "table");
		while(fgets(line, sizeof(line), arptable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line), "%s %s %s %s %s %s %s", ipaddr, hw, flag, macaddr, mask, device, tmp) == 6)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"ipaddr", ipaddr);
				blobmsg_add_string(&bb,"hw", hw);
				blobmsg_add_string(&bb,"flags", flag);
				blobmsg_add_string(&bb,"macaddr", macaddr);
				blobmsg_add_string(&bb,"mask", mask);
				blobmsg_add_string(&bb,"device", device);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(arptable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
igmp_snooping_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *snptable;
	void *t, *a;
	char line[256];
	char bridge[32];
	char device[32];
	char srcdev[32];
	char tags[32];
	char group[16];
	char mode[32];
	char RxGroup[16];
	char source[16];
	char reporter[16];
	int lantci, wantci, timeout, Index, ExcludPt;

	if ((snptable = fopen("/proc/net/igmp_snooping", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "table");
		while(fgets(line, sizeof(line), snptable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line),"%s %s %s %s %x %x %s %s %s %s %s %d %x %d",
					bridge, device, srcdev, tags, &(lantci), &(wantci),
					group, mode, RxGroup, source, reporter,
					&(timeout), &(Index), &(ExcludPt)) == 14)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"bridge", bridge);
				blobmsg_add_string(&bb,"device", device);
				blobmsg_add_string(&bb,"srcdev", srcdev);
				blobmsg_add_string(&bb,"tags", tags);
				blobmsg_add_u32(&bb,"lantci", lantci);
				blobmsg_add_u32(&bb,"wantci", wantci);
				blobmsg_add_string(&bb,"group", group);
				blobmsg_add_string(&bb,"mode", mode);
				blobmsg_add_string(&bb,"rxgroup", RxGroup);
				blobmsg_add_string(&bb,"source", source);
				blobmsg_add_string(&bb,"reporter", reporter);
				blobmsg_add_u32(&bb,"timeout", timeout);
				blobmsg_add_u32(&bb,"index", Index);
				blobmsg_add_u32(&bb,"excludpt", ExcludPt);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(snptable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
ip_conntrack_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *ipcntable;
	void *t, *a;
	char line[512];
	char state [64];
	char local_ip[24];
	char remote_ip[24];
	char tmps[64];
	int local_port, remote_port, tmpi;

	if ((ipcntable = fopen("/proc/net/ip_conntrack", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "table");
		while(fgets(line, sizeof(line), ipcntable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line),"tcp %d %d %s src=%s dst=%s sport=%d dport=%d src=%s dst=%s sport=%d dport=%d %s mark=%d use=%d",
					&tmpi, &tmpi, state, tmps, tmps, &tmpi, &tmpi, local_ip, remote_ip, &local_port, &remote_port, tmps, &tmpi, &tmpi) == 14)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"proto", "tcp");
				blobmsg_add_string(&bb,"state", state);
				blobmsg_add_string(&bb,"local_ip", local_ip);
				blobmsg_add_string(&bb,"remote_ip", remote_ip);
				blobmsg_add_u32(&bb,"local_port", local_port);
				blobmsg_add_u32(&bb,"remote_port", remote_port);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(ipcntable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
ipv4_routes_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *ipv4rtable;
	void *t, *a;
	char line[512];
	char dest[24];
	char gw[24];
	char mask [24];
	char flags[8];
	char metric[8];
	char ref[8];
	char use[8];
	char iface[16];

	if ((ipv4rtable = popen("route -n | tail -n +3", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "routes");
		while(fgets(line, sizeof(line), ipv4rtable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line), "%s %s %s %s %s %s %s %s", dest, gw, mask, flags, metric, ref, use, iface) == 8)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"destination", dest);
				blobmsg_add_string(&bb,"gateway", gw);
				blobmsg_add_string(&bb,"mask", mask);
				blobmsg_add_string(&bb,"flags", flags);
				blobmsg_add_string(&bb,"metric", metric);
				blobmsg_add_string(&bb,"ref", ref);
				blobmsg_add_string(&bb,"use", use);
				blobmsg_add_string(&bb,"iface", iface);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(ipv4rtable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
ipv6_neigh_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *ipv6nghtable;
	void *t, *a;
	char line[512];
	char ip6addr[128];
	char device[16];
	char macaddr[24];
	char router[16];
	char ip6status[16];

	if ((ipv6nghtable = popen("ip -6 neigh", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "neighbors");
		while(fgets(line, sizeof(line), ipv6nghtable) != NULL)
		{
			remove_newline(line);
			memset(router, '\0', sizeof(router));
			if(sscanf(single_space(line), "%s dev %s lladdr %s %s %s", ip6addr, device, macaddr, router, ip6status) == 5 ||
				sscanf(single_space(line), "%s dev %s lladdr %s %s", ip6addr, device, macaddr, ip6status) == 4)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"ip6addr", ip6addr);
				blobmsg_add_string(&bb,"device", device);
				blobmsg_add_string(&bb,"macaddr", macaddr);
				blobmsg_add_u8(&bb,"router", strstr(router, "router")?true:false);
				blobmsg_add_string(&bb,"ip6status", ip6status);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(ipv6nghtable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
ipv6_routes_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *ipv6rtable;
	void *t, *a;
	char line[512];
	char dest[128];
	char nhop[128];
	char flags[8];
	char metric[8];
	char ref[8];
	char use[8];
	char iface[16];

	if ((ipv6rtable = popen("route -A inet6 | tail -n +3", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "routes");
		while(fgets(line, sizeof(line), ipv6rtable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line), "%s %s %s %s %s %s %s", dest, nhop, flags, metric, ref, use, iface) == 7)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"destination", dest);
				blobmsg_add_string(&bb,"next_hop", nhop);
				blobmsg_add_string(&bb,"flags", flags);
				blobmsg_add_string(&bb,"metric", metric);
				blobmsg_add_string(&bb,"ref", ref);
				blobmsg_add_string(&bb,"use", use);
				blobmsg_add_string(&bb,"iface", iface);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(ipv6rtable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
quest_network_connections(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *f;
	void *t;
	char line[512];
	int tcp_count = 0;
	int udp_count = 0;
	char type[16], established[16], unreplied_udp[16], unreplied_tcp[16], x[32];

	blob_buf_init(&bb, 0);

	if((f = fopen("/proc/net/ip_conntrack", "r"))) {
		while(fgets(line, sizeof(line), f) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line),"%s %s %s %s %s %s %s %s %s", type, x, x, established, x, x, x, unreplied_udp, unreplied_tcp) == 9)
			{
				if(strcmp(type, "udp")==0 && strcmp(unreplied_udp,"[UNREPLIED]")!=0){
					++udp_count;
				}
				else if(strcmp(type, "tcp")==0 && strcmp(established,"ESTABLISHED")==0 && strcmp(unreplied_tcp,"[UNREPLIED]")!=0){
					++tcp_count;
				}
			}
		}
		t = blobmsg_open_table(&bb, "connections");
		blobmsg_add_u32(&bb, "TCP connections", tcp_count);
		blobmsg_add_u32(&bb, "UDP connections", udp_count);
		blobmsg_close_table(&bb, t);
		fclose(f);
	}

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

int
quest_network_load(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *f;
	void *t;
	char line[512];
	char load1[16],load5[16],load15[16];

	blob_buf_init(&bb, 0);

	if((f = fopen("/proc/loadavg", "r"))) {
		if(fgets(line, sizeof(line), f) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line),"%s %s %s", load1, load5, load15) == 3) //0.20 0.26 0.67 1/131 26760)
			{
				t = blobmsg_open_table(&bb, "load");
				blobmsg_add_string(&bb, "1 minute", load1);
				blobmsg_add_string(&bb, "5 minutes", load5);
				blobmsg_add_string(&bb, "15 minutes", load15);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(f);
	}

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}


static struct iface ifaces[MAX_IFACES];
pthread_mutex_t ifaces_lock = PTHREAD_MUTEX_INITIALIZER;

void gather_iface_traffic_data()
{
	FILE *f;
	char line[512];
	char ifname[64], rx[32], tx[32];
	int nr_of_ifaces = 0;

	void update_iface(char* name, char* rx_total, char* tx_total){
		int j;
		for(j=0; j<nr_of_ifaces; ++j){
			if(strncmp(ifaces[j].name, name, MAX_IFNAME) == 0){
				ifaces[j].rx = atol(rx_total) - ifaces[j].rx_total;
				ifaces[j].tx = atol(tx_total) - ifaces[j].tx_total;
				ifaces[j].rx_total = atol(rx_total);
				ifaces[j].tx_total = atol(tx_total);
				return;
			}
			else if(ifaces[j].name[0] == '\0'){
				strcpy(ifaces[j].name,name);
				ifaces[j].rx_total = atol(rx_total);
				ifaces[j].tx_total = atol(tx_total);
				return;
			}
		}
	}

	/* Update traffic data from /rpoc/net/dev */
	if((f = fopen("/proc/net/dev", "r"))) {
		pthread_mutex_lock(&ifaces_lock);
		nr_of_ifaces = 0;
		while(fgets(line, sizeof(line), f) != NULL)
		{
			remove_newline(line);
			// eth2: 1465340723 9488842 104 4226 0 0 0 2031000 128068095 1172071 0 0 0 0 0 0
			if(sscanf(single_space(line)," %[^:]: %s %*s %*s %*s %*s %*s %*s %*s %s", ifname, rx, tx) == 3) {
				++nr_of_ifaces;
				update_iface(ifname,rx,tx);
			}
		}
		memset(&ifaces[nr_of_ifaces], 0, sizeof(struct iface)*(MAX_IFACES-nr_of_ifaces));
		pthread_mutex_unlock(&ifaces_lock);
		fclose(f);
	}
}

static int
quest_iface_traffic(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	int i;
	void *t;
	blob_buf_init(&bb, 0);

	pthread_mutex_lock(&ifaces_lock);
	for(i=0; i<MAX_IFACES && ifaces[i].name[0]!='\0'; ++i){
		t = blobmsg_open_table(&bb, ifaces[i].name);
		blobmsg_add_u32(&bb, "Transmitted bytes", ifaces[i].tx);
		blobmsg_add_u32(&bb, "Received bytes", ifaces[i].rx);
		blobmsg_close_table(&bb, t);
	}
	pthread_mutex_unlock(&ifaces_lock);

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static int
quest_client_traffic(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	static struct ubus_request req_data;
	uint32_t id;
	int ret;

	//if (ubus_lookup_id(ctx, "router.network", &id)) {
	//	fprintf(stderr, "Failed to look up test object\n");
	//	return 1;
	//}
	//ubus_invoke(ctx, id, "clients", msg, NULL, 0, 3000);

	//blob_buf_init(&bb, 0);
	//void *t;
	//t = blobmsg_open_table(&bb, "gurka");
	//blobmsg_add_u32(&bb, "batman", id);
	//blobmsg_close_table(&bb, t);

	//ubus_send_reply(ctx, req, bb.head);
	return 0;
}

struct ubus_method net_object_methods[] = {
	UBUS_METHOD_NOARG("arp", arp_table),
	UBUS_METHOD_NOARG("igmp_snooping", igmp_snooping_table),
	UBUS_METHOD_NOARG("ip_conntrack", ip_conntrack_table),
	UBUS_METHOD_NOARG("ipv4_routes", ipv4_routes_table),
	UBUS_METHOD_NOARG("ipv6_neigh", ipv6_neigh_table),
	UBUS_METHOD_NOARG("ipv6_routes", ipv6_routes_table),
	UBUS_METHOD_NOARG("connections", quest_network_connections),
	UBUS_METHOD_NOARG("load", quest_network_load),
	UBUS_METHOD_NOARG("iface_traffic", quest_iface_traffic),
	UBUS_METHOD_NOARG("client_traffic", quest_client_traffic),
};

struct ubus_object_type net_object_type =
	UBUS_OBJECT_TYPE("net", net_object_methods);

struct ubus_object net_object = {
	.name = "router.net",
	.type = &net_object_type,
	.methods = net_object_methods,
	.n_methods = ARRAY_SIZE(net_object_methods),
};
