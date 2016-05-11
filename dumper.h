#ifndef DUMPER_H
#define DUMPER_H 1

void dump_keys(Key *keys);
void dump_specs(Spec *spec);
void dump_static_router_info(Router *router);
void dump_hostname(Router *router);
void dump_sysinfo(Router *router, Memory *memory);
void dump_cpuinfo(Router *router, jiffy_counts_t *prev_jif, jiffy_counts_t *cur_jif);

#endif /* DUMPER_H */

