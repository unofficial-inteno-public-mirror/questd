/*
 * ueventd -- ubus event daemon for Inteno CPEs
 *
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
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

#include <fcntl.h>

#include "eventd.h"

static struct ubus_event_handler event_listener;
static struct ubus_context *ctx = NULL;
static struct blob_buf bb;

static Event events[MAX_EVENT];
static int evno = 0;

static int
list_router_events(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_reevent_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *a, *t, *d;
	int i;
	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "list");
	for (i = 0; i < MAX_EVENT; i++) {
		if (!(events[i].time) || events[i].time <= ((int)time(NULL)-10))
			continue;
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "type", events[i].type);
		blobmsg_add_u32(&bb, "time", events[i].time);
		d = blobmsg_open_table(&bb, "data");
		blobmsg_add_json_from_string(&bb, events[i].data);
		blobmsg_close_table(&bb, d);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static struct ubus_method event_object_methods[] = {
	UBUS_METHOD_NOARG("list", list_router_events),
};

static struct ubus_object_type event_object_type =
	UBUS_OBJECT_TYPE("event", event_object_methods);

static struct ubus_object event_object = {
	.name = "event",
	.type = &event_object_type,
	.methods = event_object_methods,
	.n_methods = ARRAY_SIZE(event_object_methods),
};

static void 
system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static void
event_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	system_fd_set_cloexec(ctx->sock.fd);
}

static void
event_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = event_ubus_reconnect_timer,
	};
	int t = 2;

	if (ubus_reconnect(ctx, NULL) != 0) {
		printf("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	printf("reconnected to ubus, new id: %08x\n", ctx->local_id);
	event_ubus_add_fd();
}

static void
event_ubus_connection_lost(struct ubus_context *ctx)
{
	event_ubus_reconnect_timer(NULL);
}

static void
receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);

	events[evno].time = (int)time(NULL);
	strncpy(events[evno].type, type, 64);
	strncpy(events[evno].data, str, 1024);

	evno++;

	if (evno > MAX_EVENT-1)
		evno = 0;

	free(str);
}

int main(int argc, char **argv)
{
	int ret;

	uloop_init();

	ctx = ubus_connect(NULL);
	if (!ctx)
		return -EIO;

	printf("connected as %08x\n", ctx->local_id);
	ctx->connection_lost = event_ubus_connection_lost;
	event_ubus_add_fd();

	ret = ubus_add_object(ctx, &event_object);
	if (ret != 0)
		fprintf(stderr, "Failed to publish object '%s': %s\n", event_object.name, ubus_strerror(ret));

	event_listener.cb = receive_event;
	ret = ubus_register_event_handler(ctx, &event_listener, "*");
	if (ret)
		fprintf(stderr, "Couldn't register to router events\n");

	uloop_run();
	ubus_free(ctx);	

	return 0;
}
