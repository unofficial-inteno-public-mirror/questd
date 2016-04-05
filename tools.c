#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "questd.h"

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
