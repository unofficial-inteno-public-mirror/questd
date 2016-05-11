#ifndef DUMPER_H
#define DUMPER_H 1


typedef struct { /* Used by: questd.c, dumper.c, dumper.h */
	char name[64];
	char *hardware;
	char *model;
	char *boardid;
	char *firmware;
	char *brcmver;
	char *filesystem;
	char *socmod;
	char *socrev;
	char *cfever;
	char *kernel;
	char *basemac;
	char *serialno;
	char date[64];
	char uptime[64];
	unsigned int localtime;
	unsigned int procs;
	unsigned int cpu;
} Router;

typedef struct {  /* Used by: questd.c, dumper.c, dumper.h */
	unsigned long total;
	unsigned long used;
	unsigned long free;
	unsigned long shared;
	unsigned long buffers;
} Memory;

typedef struct {  /* Used by: questd.c, dumper.c, dumper.h */
	char *auth;
	char *des;
	char *wpa;
} Key;

typedef struct {  /* Used by: questd.c, dumper.c, dumper.h */
	bool wifi;
	bool adsl;
	bool vdsl;
	bool voice;
	bool dect;
	int vports;
	int eports;
} Spec;


void dump_keys(Key *keys);
void dump_specs(Spec *spec);
void dump_static_router_info(Router *router);
void dump_hostname(Router *router);
void dump_sysinfo(Router *router, Memory *memory);
void dump_cpuinfo(Router *router, jiffy_counts_t *prev_jif, jiffy_counts_t *cur_jif);

#endif /* DUMPER_H */

