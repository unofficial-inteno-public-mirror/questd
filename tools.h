#ifndef QUESTD_TOOLS_H
#define QUESTD_TOOLS_H 1
#include <uci.h>

#include <stdarg.h>

void remove_space(char *buf);
void remove_newline(char *buf);
char* trim(char *str);
void replace_char(char *buf, char a, char b);
char* convert_to_ipaddr(int ip);
char* single_space(char *str);
int is_inteno_macaddr(char *macaddr);
int is_inteno_altered_macaddr(char *macaddr);
struct uci_package * init_package(struct uci_context **ctx, const char *config);
void free_uci_context(struct uci_context **ctx);

/* system/popen variadic wrappers (printf alike) */
int systemf(const char *format, ...);
int snsystemf(char *output, size_t output_size, const char *format, ...);

/* system/popen va_arg wrappers (vprintf alike) */
int vsystemf(const char *format, va_list ap);
int vsnsystemf(char *output, size_t output_size,
		const char *format, va_list ap);

/* legacy wrappers */
void runCmd(const char *format, ...);
char *chrCmd(char *output, size_t output_size, const char *format, ...);

#endif /* QUESTD_TOOLS_H */
