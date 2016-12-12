/*
 * tools -- provides easy to use functions for questd
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

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <uci.h>

#include <netinet/in.h>
#include <arpa/inet.h>

int
is_inteno_macaddr(char *macaddr) {
	return (!strncmp(macaddr, "00:22:07", 8) || !strncmp(macaddr, "44:D4:37", 8));
}

int
is_inteno_altered_macaddr(char *macaddr) {
	return ((strncmp(macaddr, "00:22:07", 8) && strncmp(macaddr, "44:D4:37", 8)) && (!strncmp(macaddr+3, "22:07", 5) || !strncmp(macaddr+3, "D4:37", 5)));
}

void
remove_space(char *buf)
{
	char newbuf[strlen(buf)+1];
	int i = 0;
	int j = 0;

	while (buf[i]) {
		newbuf[j] = buf[i];
		if (buf[i] != ' ')
			j++;
		i++;
	}
	newbuf[j] = '\0';
	strcpy(buf, newbuf);
}

void 
remove_newline(char *buf)
{
	int len;
	len = strlen(buf) - 1;
	if (buf[len] == '\n') 
		buf[len] = 0;
}

void
replace_char(char *buf, char a, char b)
{
	int i = 0;

	while (buf[i]) {
		if (buf[i] == a)
			buf[i] = b;
		i++;
	}
	buf[i] = '\0';
}

void
runCmd(const char *pFmt, ...)
{
	va_list ap;
	char cmd[256] = {0};
	int len=0, maxLen;

	maxLen = sizeof(cmd);

	va_start(ap, pFmt);

	if (len < maxLen)
	{
		maxLen -= len;
		vsnprintf(&cmd[len], maxLen, pFmt, ap);
	}

	system(cmd);

	va_end(ap);
}

const char*
chrCmd(const char *pFmt, ...)
{
	va_list ap;
	char cmd[256] = {0};
	int len=0, maxLen;

	maxLen = sizeof(cmd);

	va_start(ap, pFmt);

	if (len < maxLen)
	{
		maxLen -= len;
		vsnprintf(&cmd[len], maxLen, pFmt, ap);
	}

	va_end(ap);

	FILE *pipe = 0;
	static char buffer[10000] = {0};
	buffer[0] = '\0';
	if ((pipe = popen(cmd, "r"))){
		fgets(buffer, sizeof(buffer), pipe);
		pclose(pipe);

		remove_newline(buffer);
		if (strlen(buffer))
			return (const char*)buffer;
		else
			return "";
	} else {
		return ""; 
	}
}

char* convert_to_ipaddr(int ip)
{
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	return inet_ntoa(ip_addr);
}

char* single_space(char* str){
	char *from, *to;
	int space = 0;
	from = to = str;
	while(1) {
		if(space && *from == ' ' && to[-1] == ' ') {
			++from;
		} else {
			space = (*from == ' ') ? 1 : 0;
			*to++ = *from++;
			if(!to[-1])
				break;
		}
	}
	return str;
}


struct uci_package *
init_package(struct uci_context **ctx, const char *config)
{
	struct uci_package *p = NULL;

	if (!*ctx) {
		*ctx = uci_alloc_context();
	} else {
		p = uci_lookup_package(*ctx, config);
		if (p)
			uci_unload(*ctx, p);
	}

	if (uci_load(*ctx, config, &p))
		return NULL;

	return p;
}

