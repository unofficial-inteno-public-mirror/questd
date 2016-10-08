/*
 * dropbear -- contains functions to handle dropbear SSH keys
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

#include "questd.h"

enum {
	SSH_PATH,
	__SSH_MAX
};

static const struct blobmsg_policy dropbear_policy[__SSH_MAX] = {
	[SSH_PATH] 	= { .name = "path",	.type = BLOBMSG_TYPE_STRING }
};

static struct blob_buf bb;

bool is_valid_key(const char *type, const char *key)
{
	int i;
	for(i = 0; i < strlen(key); i++){
		if(!isalnum(key[i]) && key[i] != '+' && key[i] != '/' && key[i] != '=')
			return false;
	}
	return ((strcmp(type, "ssh-rsa") == 0 && strncmp(key, "AAAAB3NzaC1yc2EA", 16) == 0) ||
			(strcmp(type, "ssh-dss") == 0 && strncmp(key, "AAAAB3NzaC1kc3MA", 16) == 0));
}

static int
quest_get_keys(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	FILE *file;
	char line[4176], type[16], key[4096], comment[64];
	int num;
	void *a, *t;

	blob_buf_init(&bb, 0);
	if((file = fopen("/etc/dropbear/authorized_keys", "r")) == NULL){
		blobmsg_add_string(&bb, "error", "Couldn't open /etc/dropbear/authorized_keys file");
		ubus_send_reply(ctx, req, bb.head);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
	a = blobmsg_open_array(&bb, "keys");
	while(fgets(line, 4176, file) != NULL){
		num = sscanf(line, "%16s %4096s %64s", type, key, comment);
		if(num > 1 && is_valid_key(type, key)){
			t = blobmsg_open_table(&bb, NULL);
			blobmsg_add_string(&bb, "type", type);
			blobmsg_add_string(&bb, "key", key);
			if(num == 3)
				blobmsg_add_string(&bb, "comment", comment);
			blobmsg_close_table(&bb, t);
		}
	}
	blobmsg_close_array(&bb, a);
	fclose(file);
	ubus_send_reply(ctx, req,bb.head);
	return UBUS_STATUS_OK;
}

static int
quest_add_key(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int status = UBUS_STATUS_OK, num, tmp_num;
	FILE *in_file, *out_file;
	struct blob_attr *tb[__SSH_MAX];
	char path[256], real_path[PATH_MAX], line[4176], type[16], key[4096], comment[64];
	char tmp_type[16], tmp_key[4096];

	blobmsg_parse(dropbear_policy, __SSH_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SSH_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	strncpy(path, blobmsg_get_string(tb[SSH_PATH]), 256);
	path[255] = '\0'; //make sure string is null-terminated

	if(realpath(path, real_path) == NULL){
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(strncmp(real_path, "/tmp/", 5) != 0)
		return UBUS_STATUS_PERMISSION_DENIED;

	if((in_file = fopen(real_path, "r")) == NULL)
		return UBUS_STATUS_UNKNOWN_ERROR;

	if(fgets(line, 4176, in_file) == NULL){
		status = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	num = sscanf(line, "%16s %4096s %64s", type, key, comment);
	blob_buf_init(&bb, 0);
	if(num < 2 || !is_valid_key(type, key)){
		blobmsg_add_string(&bb, "error", "Invalid key");
		ubus_send_reply(ctx, req, bb.head);
		status = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}
	if((out_file = fopen("/etc/dropbear/authorized_keys", "a+")) == NULL){
		blobmsg_add_string(&bb, "error", "Couldn't open /etc/dropbear/authorized_keys file");
		ubus_send_reply(ctx, req, bb.head);
		status = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}
	while(fgets(line, 4176, out_file) != NULL){
		tmp_num = sscanf(line, "%16s %4096s ", tmp_type, tmp_key);
		if(tmp_num < 2)
			continue;
		if(is_valid_key(tmp_type, tmp_key)){
			if(strcmp(key, tmp_key) == 0){
				blobmsg_add_string(&bb, "error", "Key already in dropbear");
				ubus_send_reply(ctx, req, bb.head);
				status = UBUS_STATUS_INVALID_ARGUMENT;
				goto close_both;
			}
		}
	}
	if(num == 2)
		snprintf(line, 4176, "%s %s\n", type, key);
	else
		snprintf(line, 4176, "%s %s %s\n", type, key, comment);
	fputs(line, out_file);
	fsync(fileno(out_file));
close_both:
	fclose(out_file);
out:
	fclose(in_file);
	return status;
}

static int
quest_del_key(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int status = UBUS_STATUS_OK, num, tmp_num;
	FILE *in_file, *out_file, *tmp_file;
	struct blob_attr *tb[__SSH_MAX];
	char path[256], real_path[PATH_MAX], line[4176], type[16], key[4096], comment[64];
	char tmp_type[16], tmp_key[4096];

	blobmsg_parse(dropbear_policy, __SSH_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SSH_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	strncpy(path, blobmsg_get_string(tb[SSH_PATH]), 256);
	path[255] = '\0'; //make sure string is null-terminated

	if(realpath(path, real_path) == NULL){
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(strncmp(real_path, "/tmp/", 5) != 0)
		return UBUS_STATUS_PERMISSION_DENIED;

	if((in_file = fopen(real_path, "r")) == NULL)
		return UBUS_STATUS_UNKNOWN_ERROR;

	if(fgets(line, 4176, in_file) == NULL){
		status = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	num = sscanf(line, "%16s %4096s %64s", type, key, comment);
	blob_buf_init(&bb, 0);
	if(num < 2 || !is_valid_key(type, key)){
		blobmsg_add_string(&bb, "error", "Invalid key");
		ubus_send_reply(ctx, req, bb.head);
		status = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}
	if((out_file = fopen("/etc/dropbear/authorized_keys", "r")) == NULL){
		blobmsg_add_string(&bb, "error", "Couldn't open /etc/dropbear/authorized_keys file");
		ubus_send_reply(ctx, req, bb.head);
		status = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}
	if((tmp_file = fopen("/etc/dropbear/authorized_keys.bak", "w")) == NULL){
		blobmsg_add_string(&bb, "error", "Couldn't open temporary file");
		ubus_send_reply(ctx, req, bb.head);
		status = UBUS_STATUS_UNKNOWN_ERROR;
		goto close_both;
	}
	while(fgets(line, 4176, out_file) != NULL){
		tmp_num = sscanf(line, "%16s %4096s ", tmp_type, tmp_key);
		if(tmp_num < 2 || !is_valid_key(tmp_type, tmp_key) || strcmp(key, tmp_key) != 0){
			fputs(line, tmp_file);
		}
	}
	fsync(fileno(tmp_file));
	fclose(in_file);
	fclose(out_file);
	fclose(tmp_file);
	if(remove("/etc/dropbear/authorized_keys") == 0){
		if(rename("/etc/dropbear/authorized_keys.bak", "/etc/dropbear/authorized_keys") != 0){
			blobmsg_add_u32(&bb, "error", errno);
			blobmsg_add_string(&bb, "errormsg", "Couldn't move tmp file to authorized_keys");
			ubus_send_reply(ctx, req, bb.head);
		}
	}else{
		blobmsg_add_u32(&bb, "error", errno);
		blobmsg_add_string(&bb, "errormsg", "Couldn't delete old authorized_keys");
		ubus_send_reply(ctx, req, bb.head);
	}
	return 0;
close_both:
	fclose(out_file);
out:
	fclose(in_file);
	return status;
}

struct ubus_method dropbear_object_methods[] = {
	UBUS_METHOD_NOARG("get_ssh_keys", quest_get_keys),
	UBUS_METHOD("add_ssh_key", quest_add_key, dropbear_policy),
	UBUS_METHOD("del_ssh_key", quest_del_key, dropbear_policy),
};

struct ubus_object_type dropbear_object_type = UBUS_OBJECT_TYPE("dropbear", dropbear_object_methods);

struct ubus_object dropbear_object = {
	.name = "router.dropbear",
	.type = &dropbear_object_type,
	.methods = dropbear_object_methods,
	.n_methods = ARRAY_SIZE(dropbear_object_methods),
};
