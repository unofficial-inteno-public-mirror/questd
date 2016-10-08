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


#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include "network.h"
#include "system.h"
#include "tools.h"

#define DEFAULT_SLEEP	5000000

static struct ubus_context *ctx = NULL;
static const char *ubus_path;

pthread_t tid[1];
pthread_mutex_t lock;
static long sleep_time = DEFAULT_SLEEP;

void recalc_sleep_time(bool calc, int toms)
{
	long dec = toms * 1000;
	if (!calc)
		sleep_time = DEFAULT_SLEEP;
	else if(sleep_time >= dec)
		sleep_time -= dec;
}

static void 
system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

extern int
quest_router_info(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

extern int
quest_router_networks(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

extern int
quest_router_clients(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

static struct ubus_method router_object_methods[] = {
	/* moved to router.system object */
	/* still here for backwards compatibility */
	UBUS_METHOD_NOARG("info", quest_router_info),

	/* moved to router.network object */
	/* still here for backwards compatibility */
	UBUS_METHOD_NOARG("networks", quest_router_networks),
	UBUS_METHOD_NOARG("clients", quest_router_clients),
};

static struct ubus_object_type router_object_type =
	UBUS_OBJECT_TYPE("router", router_object_methods);

static struct ubus_object router_object = {
	.name = "router",
	.type = &router_object_type,
	.methods = router_object_methods,
	.n_methods = ARRAY_SIZE(router_object_methods),
};

extern struct ubus_object net_object;
extern struct ubus_object network_object;
#if IOPSYS_BROADCOM
extern struct ubus_object wireless_object;
extern struct ubus_object wps_object;
extern struct ubus_object dsl_object;
extern struct ubus_object port_object;
#endif
extern struct ubus_object system_object;
extern struct ubus_object dropbear_object;
extern struct ubus_object usb_object;

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
	quest_add_object(&system_object);
	quest_add_object(&dropbear_object);
	quest_add_object(&usb_object);
	quest_add_object(&net_object);
	quest_add_object(&network_object);
#if IOPSYS_BROADCOM
	quest_add_object(&dsl_object);
	quest_add_object(&port_object);
	quest_add_object(&wireless_object);
	quest_add_object(&wps_object);
#endif

	return 0;
}

void *collect_router_info(void *arg)
{
	init_db_hw_config();
	load_networks();
#if IOPSYS_BROADCOM
	load_wireless();
#endif
	collect_system_info();
	while (true) {
		pthread_mutex_lock(&lock);
		calculate_cpu_usage();
		populate_clients();
		pthread_mutex_unlock(&lock);
		get_cpu_usage(0);
		usleep(sleep_time);
		recalc_sleep_time(false, 0);
		get_cpu_usage(1);
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
	
	if ((pt = pthread_create(&(tid[0]), NULL, &collect_router_info, NULL) != 0)) {
		fprintf(stderr, "Failed to create thread\n");
		return 1;
	}

	uloop_run();
	pthread_mutex_destroy(&lock);
	ubus_free(ctx);	

	return 0;
}

