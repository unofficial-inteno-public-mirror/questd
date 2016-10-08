typedef struct {
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

typedef struct {
	unsigned long total;
	unsigned long used;
	unsigned long free;
	unsigned long shared;
	unsigned long buffers;
} Memory;

typedef struct {
	char *auth;
	char *des;
	char *wpa;
} Key;

typedef struct {
	bool wifi;
	bool adsl;
        bool vdsl;
        bool voice;
        bool dect;
        int vports;
	int eports;
} Spec;

typedef struct jiffy_counts_t {
	unsigned long long usr, nic, sys, idle;
	unsigned long long iowait, irq, softirq, steal;
	unsigned long long total;
	unsigned long long busy;
} jiffy_counts_t;

void get_cpu_usage(int p);
void collect_system_info(void);
void calculate_cpu_usage(void);
void dump_sysinfo(Router *router, Memory *memory);
void dump_keys(Key *keys);
void dump_specs(Spec *spec);
void dump_static_router_info(Router *router);
void dump_hostname(Router *router);
void dump_cpuinfo(Router *router, jiffy_counts_t *prev_jif, jiffy_counts_t *cur_jif);
void get_jif_val(jiffy_counts_t *p_jif);
void init_db_hw_config(void);
