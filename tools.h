#ifndef QUESTD_TOOLS_H
#define QUESTD_TOOLS_H 1
#include <uci.h>

void remove_space(char *buf);
void remove_newline(char *buf);
void replace_char(char *buf, char a, char b);
void runCmd(const char *pFmt, ...);
void get_db_value(const char *name, char **value);
const char* chrCmd(const char *pFmt, ...);
char* convert_to_ipaddr(int ip);
char* single_space(char *str);
int is_inteno_macaddr(char *macaddr);
int is_inteno_altered_macaddr(char *macaddr);
struct uci_package * init_package(struct uci_context **ctx, const char *config);
void free_uci_context(struct uci_context **ctx);

#endif /* QUESTD_TOOLS_H */
