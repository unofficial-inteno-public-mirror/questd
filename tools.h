#ifndef QUESTD_TOOLS_H
#define QUESTD_TOOLS_H 1
#include <uci.h>

void remove_space(char *buf);
void remove_newline(char *buf);
void replace_char(char *buf, char a, char b);
void runCmd(const char *pFmt, ...);
const char* chrCmd(const char *pFmt, ...);
char* convert_to_ipaddr(int ip);
char* single_space(char *str);
int is_inteno_macaddr(char *macaddr);
int is_inteno_altered_macaddr(char *macaddr);
struct uci_package * init_package(struct uci_context **ctx, const char *config);

#endif /* QUESTD_TOOLS_H */
