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
				sscanf(single_space(line), "%s dev %s lladdr %s %s %s", ip6addr, device, macaddr, ip6status) == 4)
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

struct ubus_method net_object_methods[] = {
	UBUS_METHOD_NOARG("arp", arp_table),
	UBUS_METHOD_NOARG("igmp_snooping", igmp_snooping_table),
	UBUS_METHOD_NOARG("ip_conntrack", ip_conntrack_table),
	UBUS_METHOD_NOARG("ipv4_routes", ipv4_routes_table),
	UBUS_METHOD_NOARG("ipv6_neigh", ipv6_neigh_table),
	UBUS_METHOD_NOARG("ipv6_routes", ipv6_routes_table),
};

struct ubus_object_type net_object_type =
	UBUS_OBJECT_TYPE("net", net_object_methods);

struct ubus_object net_object = {
	.name = "router.net",
	.type = &net_object_type,
	.methods = net_object_methods,
	.n_methods = ARRAY_SIZE(net_object_methods),
};
