#ifndef NDISC_H
#define NDISC_H 1

void clear_macaddr(void);
char *get_macaddr(void);
bool ndisc(const char *name, const char *ifname, unsigned flags,
	unsigned retry, unsigned wait_ms);

#endif /* NDISC_H */

