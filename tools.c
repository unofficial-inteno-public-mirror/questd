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

#include "tools.h"

#define QD_LINE_MAX 2048

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


int systemf(const char *format, ...)
{
	int rv;
	va_list ap;

	va_start(ap, format);
	rv = vsystemf(format, ap);
	va_end(ap);

	return rv;
}

int snsystemf(char *output, size_t output_size, const char *format, ...)
{
	int rv;
	va_list ap;

	va_start(ap, format);
	rv = vsnsystemf(output, output_size, format, ap);
	va_end(ap);

	return rv;
}


int vsystemf(const char *format, va_list ap)
{
	int rv;

	rv = vsnsystemf(NULL, 0, format, ap);

	return rv;
}

int vsnsystemf(char *output, size_t output_size, const char *format, va_list ap)
{
	int n, rv = 0;
	size_t cmdline_size = 256;
	char *cmdline = NULL, *new_cmdline;

	cmdline = (char *)malloc(cmdline_size * sizeof(char));
	if (!cmdline)
		goto out;

	while (1) {
		memset(cmdline, 0, cmdline_size);

		n = vsnprintf(cmdline, cmdline_size, format, ap);

		if (n < 0)
			goto out_cmdline;
		if (n < cmdline_size)
			break; /* good */

		/* else try again with more space */
		cmdline_size += 32;
		new_cmdline = (char *) realloc(cmdline,
						cmdline_size * sizeof(char));
		if (!new_cmdline)
			goto out_cmdline;
		cmdline = new_cmdline;
	}

	FILE *stream;
	char *line;

	stream = popen(cmdline, "r");
	if (!stream)
		goto out_stream;

	if (!output || !(output_size > 0))
		goto out_no_output;

	line = (char *) malloc(QD_LINE_MAX * sizeof(char));
	if (!line)
		goto out_line;

	memset(output, 0, output_size);
	while (fgets(line, QD_LINE_MAX, stream)) {
		int remaining = output_size - strlen(output) - 1;

		if (remaining <= 0)
			break;
		strncat(output, line, remaining);
	}

out_line:
	free(line);
out_no_output:
out_stream:
	rv = pclose(stream);
out_cmdline:
	free(cmdline);
out:
	return rv;
}


/* legacy wrappers */

/* runCmd is an alias for systemf, calls directly vsystemf */
void runCmd(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsystemf(format, ap);
	va_end(ap);
}

/* chrCmd is an alias for snsystemf, calls directly vsnsystemf */
char *chrCmd(char *output, size_t output_size, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsnsystemf(output, output_size, format, ap);
	va_end(ap);

	return output;
}


struct uci_package *init_package(struct uci_context **ctx, const char *config)
{
	struct uci_package *p = NULL;

	if (*ctx == NULL) {
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

void free_uci_context(struct uci_context **ctx)
{
	if(*ctx)
		uci_free_context(*ctx);
	*ctx = NULL;
}
