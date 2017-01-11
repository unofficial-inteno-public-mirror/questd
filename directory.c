/*
 * directory -- provides router.directory object of questd
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
	char newName[PATH_MAX];
	void *t1, *t2;
	int n, i;

	n = scandir(name, &namelist, 0, alphasort);
	if (n < 0) //got error
		return;
	for (i = 0; i < n; i++) {
		if(strcmp(namelist[i]->d_name, ".") == 0 || strcmp(namelist[i]->d_name, "..") == 0)
			continue;
		if(namelist[i]->d_type != DT_DIR)
			continue;
		t1 = blobmsg_open_table(&bb, namelist[i]->d_name);
		snprintf(newName, PATH_MAX, "%s/%s", name, namelist[i]->d_name);
		blobmsg_add_string(&bb, "path", newName);
		t2 = blobmsg_open_table(&bb, "children");
		put_folders(newName);
		blobmsg_close_table(&bb, t2);
		blobmsg_close_table(&bb, t1);
	}
	for (i = 0; i < n; i++){
		free(namelist[i]);
	}
	free(namelist);
}

bool
is_valid_path(const char *path){
	int ret;
	struct stat buf;

	ret = stat(path, &buf);
	if(ret != 0) //couldn't stat file
		return false;
	if(S_ISDIR(buf.st_mode) == 0) // is not a directory
		return false;
	ret = strncmp("/mnt/", path, 5);
	ret *= strcmp("/mnt", path);
	if(ret != 0)
		return false;
	return true;
}

void fill_folders(char *path, const char *string)
{
	struct dirent **namelist;
	int i, n;
	char full_name[PATH_MAX];

	n = scandir(path, &namelist, 0, alphasort);
	if(n < 0) //got error
		return;
	for(i = 0; i < n; i++){
		// first remove any files and unwanted folders
		if(namelist[i]->d_type != DT_DIR || strcmp(namelist[i]->d_name, ".") == 0
				|| strcmp(namelist[i]->d_name, "..") == 0)
			continue;
		if(strncmp(namelist[i]->d_name, string, strlen(string)) == 0){
			snprintf(full_name, PATH_MAX, "%s/%s", path, namelist[i]->d_name);
			blobmsg_add_string(&bb, NULL, full_name);
		}
	}
	for(i = 0; i < n; i++){
		free(namelist[i]);
	}
	free(namelist);
}

static int
quest_router_folder_tree(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *t1, *t2;
	char *path;
	struct blob_attr *tb[__DIR_MAX];
	char real_path[PATH_MAX];
	char *res;

	blobmsg_parse(dir_policy, __DIR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[PATH])
		path = "/mnt";
	else
		path = blobmsg_get_string(tb[PATH]);

	res = realpath(path, real_path);

	if(res == NULL || !is_valid_path(real_path))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&bb, 0);
	t1 = blobmsg_open_table(&bb, basename(real_path));
	blobmsg_add_string(&bb, "path", real_path);
	t2 = blobmsg_open_table(&bb, "children");

	put_folders(real_path);
	blobmsg_close_table(&bb, t2);
	blobmsg_close_table(&bb, t1);
	ubus_send_reply(ctx, req, bb.head);
	return UBUS_STATUS_OK;
}

static int
quest_router_autocomplete(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DIR_MAX];
	char real_path[PATH_MAX], copy[PATH_MAX];
	char *path, *full_path, *string;
	void *a;

	blobmsg_parse(dir_policy, __DIR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[PATH])
		goto error;

	full_path = blobmsg_get_string(tb[PATH]);

	if(full_path[strlen(full_path) - 1] == '/'){
		path = full_path;
		string = "";
	}else{
		snprintf(copy, PATH_MAX - 1, full_path);
		path = dirname(copy);
		string = basename(full_path);
	}

	if(realpath(path, real_path) == NULL)
		goto error;
	if(!is_valid_path(real_path))
		goto error;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "folders");

	fill_folders(real_path, string);

	blobmsg_close_table(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	return UBUS_STATUS_OK;
error:
	return UBUS_STATUS_INVALID_ARGUMENT;
}

struct ubus_method directory_object_methods[] = {
	UBUS_METHOD("folder_tree", quest_router_folder_tree, dir_policy),
	UBUS_METHOD("autocomplete", quest_router_autocomplete, dir_policy),
};

struct ubus_object_type directory_object_type = UBUS_OBJECT_TYPE("directory", directory_object_methods);

struct ubus_object directory_object = {
	.name = "router.directory",
	.type = &directory_object_type,
	.methods = directory_object_methods,
	.n_methods = ARRAY_SIZE(directory_object_methods),
};
