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

#include "questd.h"
#include "network.h"
#include "system.h"
#include "net.h"
#include "tools.h"

static struct ubus_context *ctx = NULL;
static const char *ubus_path;

static pthread_t tid[1];
static pthread_mutex_t lock;
static long sleep_time = INTERVAL;

void recalc_sleep_time(bool calc, int toms)
{
	long dec = toms * 1000;
	if (!calc)
		sleep_time = INTERVAL;
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

	quest_add_object(&system_object);
	quest_add_object(&dropbear_object);
	quest_add_object(&usb_object);
	quest_add_object(&net_object);
	quest_add_object(&network_object);
	quest_add_object(&dsl_object);
	quest_add_object(&wps_object);
	quest_add_object(&port_object);
	quest_add_object(&wireless_object);

	return 0;
}

void *collect_router_info(void *arg)
{
	init_db_hw_config();
	load_networks();
	load_wireless();
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

		gather_iface_traffic_data();
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

