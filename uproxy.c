/*
 * uproxyd -- ubus proxy daemon for Inteno CPEs
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

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "tools.h"

static struct ubus_context *ctx = NULL;
static struct blob_buf bb;

static int
uproxy_run(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	const char *str = blobmsg_format_json(msg, true);
	char objname[64] = {0};
	//const char *result;

	strncpy(objname, chrCmd("echo %s | awk -F'/' '{print$NF}'", obj->name), 64);

	if(strlen(objname))
		//result = chrCmd("ubus call %s %s '%s'", objname, method, str);
		runCmd("ubus call %s %s '%s'", objname, method, str);

/*	blob_buf_init(&bb, 0);*/
/*	blobmsg_add_json_from_string(&bb, result);*/
/*	ubus_send_reply(ctx, req, bb.head);*/

	return 0;
}

static void 
system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static void
uproxy_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	system_fd_set_cloexec(ctx->sock.fd);
}

static void
uproxy_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = uproxy_ubus_reconnect_timer,
	};
	int t = 2;

	if (ubus_reconnect(ctx, NULL) != 0) {
		printf("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	printf("reconnected to ubus, new id: %08x\n", ctx->local_id);
	uproxy_ubus_add_fd();
}

static void
uproxy_ubus_connection_lost(struct ubus_context *ctx)
{
	uproxy_ubus_reconnect_timer(NULL);
}

static void
uproxy_add_object(struct ubus_object *obj)
{
	int ret = ubus_add_object(ctx, obj);

	if (ret != 0)
		fprintf(stderr, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
}

void
remove_quote(char *buf)
{
	char newbuf[strlen(buf)+1];
	int i = 0;
	int j = 0;

	while (buf[i]) {
		newbuf[j] = buf[i];
		if (buf[i] != '\'')
			j++;
		i++;
	}
	newbuf[j] = '\0';
	strcpy(buf, newbuf);
}

void
remove_tab(char *buf)
{
	char newbuf[strlen(buf)+1];
	int i = 0;
	int j = 0;

	while (buf[i]) {
		newbuf[j] = buf[i];
		if (buf[i] != '\t')
			j++;
		i++;
	}
	newbuf[j] = '\0';
	strcpy(buf, newbuf);
}


int main(int argc, char **argv)
{
        int ret;
	char ipaddr[32] = {0};

get_ip:
	strncpy(ipaddr, chrCmd(". /lib/functions/network.sh && network_get_ipaddr ipaddr wan && echo $ipaddr"), 32);
	while(strlen(ipaddr) < 4) {
		usleep(2000000);
		goto get_ip;
	}

        uloop_init();

        ctx = ubus_connect(NULL);
        if (!ctx)
                return -EIO;

        printf("connected as %08x\n", ctx->local_id);
        ctx->connection_lost = uproxy_ubus_connection_lost;
        uproxy_ubus_add_fd();

	struct ubus_method *jobj_methods;
	struct ubus_object_type jobj_type;
	struct ubus_object *jobj;
        FILE *ulist;
        int i = 0;
        char name[64];
        char line[256];
        char objname[64];
        char method[64];
        char args[128];
        char objid[32];
	char mthd[64];
	struct ubus_method *jmthd;

        if ((ulist = popen("ubus list -v | tail -58 | head -17", "r"))) {
                while(fgets(line, sizeof(line), ulist) != NULL)
                {
                        remove_newline(line);
                        remove_quote(line);
                        remove_tab(line);
                        if (sscanf(line, "%s %s", objname, objid) == 2) {

				if(i == 0)
					goto name_object;

				jobj = malloc(sizeof(struct ubus_object));
				memset(jobj, 0, sizeof(struct ubus_object));
				memset(&jobj_type, 0, sizeof(struct ubus_object_type));

				jobj_type.name = "remote";
				jobj_type.id = 0;
				jobj_type.n_methods = i;
				jobj_type.methods = jobj_methods;

/*				jobj_type = (struct ubus_object_type) UBUS_OBJECT_TYPE("remote", jobj_methods);*/

				jobj->name      = strdup(name);
				jobj->methods	= jobj_methods;
				jobj->n_methods = i;
				jobj->type = &jobj_type;

				printf("Adding object %s with %d method\n", name, i);
				uproxy_add_object(jobj);

name_object:
				snprintf(name, 64, "%s/%s", ipaddr, objname);
				printf("Object name is %s\n", name);

				memset(jobj_methods, 0, sizeof(jobj_methods));

                                i = 0;

                        } else if (sscanf(line, "%s:%s", method, args) > 0) {
				snprintf(mthd, 64, chrCmd("echo %s | awk -F'[\",:]' '{print$1}'", method));
				if(strlen(mthd)) {
                                	printf("%d. method of object %s is %s\n", (i+1), name, mthd);
/*		                        jobj_methods[i].name = mthd;*/
/*					jobj_methods[i].handler = uproxy_run;*/
					jmthd = (struct ubus_method*)&jobj_methods[i];
					jmthd->name = strdup(mthd);
					jmthd->handler = uproxy_run;
/*					jobj_methods[i] = (struct ubus_method) UBUS_METHOD_NOARG(mthd, uproxy_run);*/

		                        i++;
				}
                        }
                }
		memset(jobj_methods, 0, sizeof(jobj_methods));
                pclose(ulist);
        }

        uloop_run();
        ubus_free(ctx); 

        return 0;
}
