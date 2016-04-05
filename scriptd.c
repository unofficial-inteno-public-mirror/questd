/*
 * uscriptd -- ubus script daemon for Inteno CPEs
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
#include <dirent.h>

static struct ubus_context *ctx = NULL;
static struct blob_buf bb;

enum {
	METHOD,
	ARGS,
	__SCRIPT_MAX,
};

static const struct blobmsg_policy script_policy[__SCRIPT_MAX] = {
	[METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
	[ARGS] = { .name = "args", .type = BLOBMSG_TYPE_STRING },
};

static int
script_run(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_rescript_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__SCRIPT_MAX];

	blobmsg_parse(script_policy, __SCRIPT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[METHOD]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	char *result;

	if (tb[ARGS])
		result = chrCmd("./usr/lib/ubus%s %s '%s'", obj->name, blobmsg_get_string(tb[METHOD]), blobmsg_get_string(tb[ARGS]));
	else
		result = chrCmd("./usr/lib/ubus%s %s", obj->name, blobmsg_get_string(tb[METHOD]));

	blob_buf_init(&bb, 0);
	blobmsg_add_json_from_string(&bb, result);
	ubus_send_reply(ctx, req, bb.head);

	memset(result, '\0', sizeof(result));

	return 0;
}

static struct ubus_method script_object_methods[] = {
	UBUS_METHOD("run", script_run, script_policy),
};

static struct ubus_object_type script_object_type = UBUS_OBJECT_TYPE("script", script_object_methods);

static void 
system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static void
script_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	system_fd_set_cloexec(ctx->sock.fd);
}

static void
script_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = script_ubus_reconnect_timer,
	};
	int t = 2;

	if (ubus_reconnect(ctx, NULL) != 0) {
		printf("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	printf("reconnected to ubus, new id: %08x\n", ctx->local_id);
	script_ubus_add_fd();
}

static void
script_ubus_connection_lost(struct ubus_context *ctx)
{
	script_ubus_reconnect_timer(NULL);
}

static void
script_add_object(struct ubus_object *obj)
{
	int ret = ubus_add_object(ctx, obj);

	if (ret != 0)
		fprintf(stderr, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
}

static void
add_object_foreach(char *path)
{
	struct ubus_object *jobj;
	DIR *dir;
	struct dirent *ent;
	char name[64];

	if ((dir = opendir (path)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..") || ent->d_type == DT_DIR)
				continue;
			snprintf(name, 64, "/juci/%s", ent->d_name);

			jobj = malloc(sizeof(struct ubus_object));
			memset(jobj, 0, sizeof(struct ubus_object));
			snprintf(name, 64, "/juci/%s", ent->d_name);
			jobj->name      = strdup(name);
			jobj->methods   = script_object_methods;
			jobj->n_methods = ARRAY_SIZE(script_object_methods);
			jobj->type      = &script_object_type;
			script_add_object(jobj);
		}
		closedir (dir);
	} else {
		perror ("Could not open directory");
	}
}

int main(int argc, char **argv)
{
	int ret;

	uloop_init();

	ctx = ubus_connect(NULL);
	if (!ctx)
		return -EIO;

	printf("connected as %08x\n", ctx->local_id);
	ctx->connection_lost = script_ubus_connection_lost;
	script_ubus_add_fd();

	add_object_foreach("/usr/lib/ubus/juci");

	uloop_run();
	ubus_free(ctx);	

	return 0;
}
