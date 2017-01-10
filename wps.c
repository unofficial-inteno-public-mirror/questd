/*
 * network -- provides router.wps object of questd
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

enum {
	PIN,
	__PIN_MAX,
};

static const struct blobmsg_policy pin_policy[__PIN_MAX] = {
	[PIN] = { .name = "pin", .type = BLOBMSG_TYPE_STRING },
};

static struct blob_buf bb;

static int
wps_status(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	char status[16];
	char output[32];
	int code = atoi(chrCmd(output, 32, "nvram get wps_proc_status"));

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

	sprintf(cmnd, "nvram get wps_device_pin 2>/dev/null");
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


struct ubus_method wps_object_methods[] = {
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

struct ubus_object_type wps_object_type =
	UBUS_OBJECT_TYPE("wps", wps_object_methods);

struct ubus_object wps_object = {
	.name = "router.wps",
	.type = &wps_object_type,
	.methods = wps_object_methods,
	.n_methods = ARRAY_SIZE(wps_object_methods),
};
