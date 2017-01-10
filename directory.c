/*
 * system -- provides router.system object of questd
 *
 * Copyright (C) 2012-2013 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: reidar.cederqvist@inteno.se
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

#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <dirent.h>

#include "tools.h"

static struct blob_buf bb;

enum {
	PATH,
	__DIR_MAX
};

static const struct blobmsg_policy dir_policy[__DIR_MAX] = {
	[PATH]     = { .name = "path",     .type = BLOBMSG_TYPE_STRING },
};

void
put_folders(const char *name){
	struct dirent **namelist;
	char *newName;
	void *t1, *t2;
	int n, i;

	n = scandir(name, &namelist, 0, alphasort);
	if (n < 0)
		return;
	for (i = 0; i < n; i++) {
		if(strcmp(namelist[i]->d_name, ".") == 0 || strcmp(namelist[i]->d_name, "..") == 0)
			continue;
		if(namelist[i]->d_type != DT_DIR)
			continue;
		newName = calloc(sizeof(char), strlen(name) + strlen(namelist[i]->d_name) + 1 + 1);
		if(!newName)
			continue;
		t1 = blobmsg_open_table(&bb, namelist[i]->d_name);
		snprintf(newName, (strlen(name) + strlen(namelist[i]->d_name) + 1 + 1), "%s/%s", name, namelist[i]->d_name);
		blobmsg_add_string(&bb, "path", newName);
		t2 = blobmsg_open_table(&bb, "children");
		put_folders(newName);
		blobmsg_close_table(&bb, t2);
		blobmsg_close_table(&bb, t1);
		free(newName);
		free(namelist[i]);
	}
	free(namelist);
}

bool
is_folder_in_temp(const char *path){
	int ret;

	ret = strncmp("/mnt/", path, 5);
	ret *= strcmp("/mnt", path);
	if(ret != 0)
		return false;
	return true;
}

static int
quest_router_folder_tree(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *t1, *t2;
	int ret;
	char real_path[PATH_MAX];
	char *path, res;
	struct stat buf;
	struct blob_attr *tb[__DIR_MAX];

	blobmsg_parse(dir_policy, __DIR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[PATH]){
		goto error;
	}

	path = blobmsg_data(tb[PATH]);

	res = realpath(path, real_path);
	if(res == NULL)
		goto error;

	ret = stat(real_path, &buf);
	if(ret != 0) //couldn't stat file
				goto error;
	if(S_ISDIR(buf.st_mode) == 0) // is not a directory
			goto error;

	if(!is_folder_in_temp(real_path))
				goto error;

	blob_buf_init(&bb, 0);
	t1 = blobmsg_open_table(&bb, basename(real_path));
	blobmsg_add_string(&bb, "path", real_path);
	t2 = blobmsg_open_table(&bb, "children");

	put_folders(real_path);
	blobmsg_close_table(&bb, t2);
	blobmsg_close_table(&bb, t1);
	ubus_send_reply(ctx, req, bb.head);
	return UBUS_STATUS_OK;
error:
	return UBUS_STATUS_INVALID_ARGUMENT;
}

struct ubus_method directory_object_methods[] = {
	UBUS_METHOD("folder_tree", quest_router_folder_tree, dir_policy),
};

struct ubus_object_type directory_object_type = UBUS_OBJECT_TYPE("directory", directory_object_methods);

struct ubus_object directory_object = {
	.name = "router.directory",
	.type = &directory_object_type,
	.methods = directory_object_methods,
	.n_methods = ARRAY_SIZE(directory_object_methods),
};
