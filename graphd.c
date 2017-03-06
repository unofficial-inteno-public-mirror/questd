/*
 * graphd -- daemon collecting router info for realtime graphs
 *
 * Copyright (C) 2012-2013 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: christopher.nagy@inteno.se
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "tools.h"
#include "questd.h"

// h file?
#define MAX_MSG_LEN 10000
#define MAX_NAME_LEN 32
#define MAX_IFACES 32
#define MAX_CLIENTS 32

typedef struct network_node {
	unsigned long rx_total, tx_total;
	unsigned long rx, tx;
	char name[MAX_NAME_LEN];
} network_node;

static struct network_node ifaces[MAX_IFACES];
static struct network_node clients[MAX_CLIENTS];
pthread_mutex_t ifaces_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

void gather_iface_traffic_data(void); //TODO REMOVE?
void gather_client_traffic_data(void);

unsigned int thread_tick = 4000;
// h file?

static pthread_t tid[1];
static struct ubus_context *ctx = NULL;
static struct blob_buf bb;


//TODO COMMENT
void update_node(char *name, char *rx_total, char *tx_total, struct network_node nodes[], int nodes_len)
{
	int j;

	for (j = 0; j < nodes_len; ++j) {
		if (strncmp(nodes[j].name, name, MAX_NAME_LEN) == 0) {
			nodes[j].rx = atol(rx_total) - nodes[j].rx_total;
			nodes[j].tx = atol(tx_total) - nodes[j].tx_total;
			nodes[j].rx_total = atol(rx_total);
			nodes[j].tx_total = atol(tx_total);
			return;
		}
		else if (nodes[j].name[0] == '\0') {
			strcpy(nodes[j].name, name);
			nodes[j].rx_total = atol(rx_total);
			nodes[j].tx_total = atol(tx_total);
			return;
		}
	}
}



int system_call(char *command, char *output)
{
	FILE *fp;
	char str[255];

	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Failed to run command %s\n", command);
		return -1;
	}

	output[0] = '\0';

	while (fgets(str, sizeof(str)-1, fp) != NULL) {
		strcat(output, str);
	}

	pclose(fp);

	return 0;
}

//TODO: MOVE TO TOOLS
void json_get_var(json_object *obj, char *var, char *value)
{
	json_object_object_foreach(obj, key, val) {
		if (!strcmp(key, var)) {
			switch (json_object_get_type(val)) {
				case json_type_object:
					break;
				case json_type_array:
					break;
				case json_type_string:
					sprintf(value, "%s", json_object_get_string(val));
					break;
				case json_type_boolean:
					sprintf(value, "%d", json_object_get_boolean(val));
					break;
				case json_type_int:
					sprintf(value, "%d", json_object_get_int(val));
					break;
				default:
					break;
			}
		}
	}
}

int show_load(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *f;
	void *t;
	char line[512];
	char load1[16], load5[16], load15[16];

	blob_buf_init(&bb, 0);

	//TODO COMMENT
	f = fopen("/proc/loadavg", "r");
	if (f) {
		if (fgets(line, sizeof(line), f) != NULL) {
			remove_newline(line);
			if (sscanf(single_space(line), "%s %s %s", load1, load5, load15) == 3) { //0.20 0.26 0.67 1/131 26760)
				t = blobmsg_open_table(&bb, "load");
				blobmsg_add_string(&bb, "1 minute", load1);
				blobmsg_add_string(&bb, "5 minutes", load5);
				blobmsg_add_string(&bb, "15 minutes", load15);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(f);
	}

	//TODO COMMENT
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

int show_connections(struct ubus_context *ctx, struct ubus_object *obj,
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

	f = fopen("/proc/net/ip_conntrack", "r");
	if (f) {
		while (fgets(line, sizeof(line), f) != NULL) {
			remove_newline(line);
			if (sscanf(single_space(line), "%s %s %s %s %s %s %s %s %s %s %s", x, x, type, x, x, established, x, x, x, unreplied_udp, unreplied_tcp) == 11) {
				if (strcmp(type, "udp") == 0 && strcmp(unreplied_udp, "[UNREPLIED]") != 0) {
					++udp_count;
				}
				else if (strcmp(type, "tcp") == 0 && strcmp(established, "ESTABLISHED") == 0 && strcmp(unreplied_tcp, "[UNREPLIED]") != 0) {
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

void gather_iface_traffic_data(void)
{
	FILE *f;
	char line[512];
	char ifname[MAX_NAME_LEN], rx[32], tx[32];
	int nr_of_ifaces  = 0;

	/* Update traffic data from /rpoc/net/dev */
	f = fopen("/proc/net/dev", "r");
	if (f) {//TODO REVERT LOGIC, !DO TWO STUFF IN ONE LINE NEXT TIME MIGHT BE TROETT
		pthread_mutex_lock(&ifaces_lock);
		while (fgets(line, sizeof(line), f) != NULL) {
			remove_newline(line);
			// eth2: 1465340723 9488842 104 4226 0 0 0 2031000 128068095 1172071 0 0 0 0 0 0
			if (sscanf(single_space(line), " %[^:]: %s %*s %*s %*s %*s %*s %*s %*s %s", ifname, rx, tx) == 3) {
				++nr_of_ifaces;
				update_node(ifname, rx, tx, ifaces, MAX_IFACES);
			}
		}
		memset(&ifaces[nr_of_ifaces], 0, sizeof(struct network_node)*(MAX_IFACES-nr_of_ifaces));
		pthread_mutex_unlock(&ifaces_lock);
		fclose(f);
	}
}

static int show_iface_traffic(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	int i;
	void *t;
	blob_buf_init(&bb, 0);

	pthread_mutex_lock(&ifaces_lock);
	for (i = 0; i < MAX_IFACES && ifaces[i].name[0] != '\0'; ++i) {
		t = blobmsg_open_table(&bb, ifaces[i].name);
		blobmsg_add_u32(&bb, "Received bytes", ifaces[i].rx);
		blobmsg_add_u32(&bb, "Transmitted bytes", ifaces[i].tx);
		blobmsg_close_table(&bb, t);
	}
	pthread_mutex_unlock(&ifaces_lock);

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

//TODO COLLECT? REMOVE DATA?
void gather_client_traffic_data(void)
{
	char clname[MAX_NAME_LEN], rx[32], tx[32];
	int nr_of_clients = 0;
	char ubus_call_output[MAX_MSG_LEN];
	struct json_object_iter iter;

	/* Update traffic data from ubus call router.network clients*/
	system_call("ubus call router.network clients", ubus_call_output);

	json_object *output_obj = json_tokener_parse(ubus_call_output);
	json_object *wireless_obj = NULL;

	pthread_mutex_lock(&clients_lock);
	// {"client-2": {"wireless": true, "hostname": "android-30ewer203r92", "tx_bytes": 1233, "rx_bytes": 2321}}
	json_object_object_foreachC(output_obj, iter)
	{
		//TODO IF NOT CONTINUE
		if (json_object_object_get_ex(iter.val, "wireless", &wireless_obj)) {
			const char *wireless_str = json_object_to_json_string(wireless_obj);
			if (strcmp(wireless_str, "true") == 0) {
				json_get_var(iter.val, "rx_bytes", tx); //router.network clients inverts rx/tx
				json_get_var(iter.val, "tx_bytes", rx); //router.network clients inverts rx/tx
				json_get_var(iter.val, "hostname", clname);
				++nr_of_clients;
				update_node(clname, rx, tx, clients, MAX_CLIENTS);
			}
		}
	}
	memset(&clients[nr_of_clients], 0, sizeof(struct network_node)*(MAX_CLIENTS-nr_of_clients));
	pthread_mutex_unlock(&clients_lock);
}

static int show_client_traffic(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	int i;
	void *t;

	blob_buf_init(&bb, 0);

	pthread_mutex_lock(&clients_lock);
	for (i = 0; i < MAX_CLIENTS && clients[i].name[0] != '\0'; ++i) {
		t = blobmsg_open_table(&bb, clients[i].name);
		blobmsg_add_u32(&bb, "Received bytes", clients[i].rx);
		blobmsg_add_u32(&bb, "Transmitted bytes", clients[i].tx);
		blobmsg_close_table(&bb, t);
	}
	pthread_mutex_unlock(&clients_lock);

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

struct ubus_method graph_object_methods[] = {
	UBUS_METHOD_NOARG("load", show_load),
	UBUS_METHOD_NOARG("connections", show_connections),
	UBUS_METHOD_NOARG("iface_traffic", show_iface_traffic),
	UBUS_METHOD_NOARG("client_traffic", show_client_traffic),
};

struct ubus_object_type graph_object_type =
	UBUS_OBJECT_TYPE("graph", graph_object_methods);

struct ubus_object graph_object = {
	.name = "router.graph",
	.type = &graph_object_type,
	.methods = graph_object_methods,
	.n_methods = ARRAY_SIZE(graph_object_methods),
};

static void add_object(struct ubus_object *obj)
{
	int ret = ubus_add_object(ctx, obj);

	if (ret != 0)
		fprintf(stderr, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
}

void *thread_loop(void *arg)
{
	while (true) {
		gather_iface_traffic_data();
		gather_client_traffic_data();
		usleep(thread_tick*1000);
	}

	return NULL;
}

static void init_threads(void)
{
	int pt = pthread_create(&(tid[0]), NULL, &thread_loop, NULL);

	if (pt != 0)
		fprintf(stderr, "Failed to create thread\n");
}

static void init_ubus(void)
{
	uloop_init();
	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		exit(1);
	}
	ubus_add_uloop(ctx);
}

int main(int argc, char **argv)
{
	init_ubus();
	add_object(&graph_object);
	init_threads();

	uloop_run();

	pthread_mutex_destroy(&clients_lock);
	pthread_mutex_destroy(&ifaces_lock);
	ubus_free(ctx);

	return 0;
}
