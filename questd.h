//#define _GNU_SOURCE 

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <uci.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <libubus.h>

#if IOPSYS_BROADCOM
#include "broadcom.h" // WILL NOT BE NEEDED LATER
#endif

#ifndef QUESTD_H
#define QUESTD_H 1

#define MAX_RADIO	4
#define MAX_VIF		8
#define MAX_NETWORK	16
#define MAX_CLIENT	128
#define MAX_PORT	8
#define MAX_USB		18
#define MAX_IGMP_ENTRY	128

#if 0 /* UNUSED */
typedef struct {
	bool brcm;
	bool wme;
	bool ps;
	bool nonerp;
	bool apsd_be;
	bool apsd_bk;
	bool apsd_vi;
	bool apsd_vo;
	bool n_cap;
	bool vht_cap;
	bool ampdu_cap;
	bool amsdu_cap;
	bool mimo_ps;
	bool mimo_rts;
	bool rifs_cap;
	bool dwds_cap;
	bool dwds_active;
	bool scbstats;
} Flags;
#endif

#if 0 /* UNUSED */
typedef struct {
	bool ldpc;
	bool bw40;
	bool gf;
	bool sgi20;
	bool sgi40;
	bool tx_stbc;
	bool rx_stbc;
	bool delayed_ba;
	bool intl40;
} HTCaps;
#endif

#if 0 /* UNUSED */
typedef struct {
	bool ldpc;
	bool sgi80;
	bool sgi160;
	bool tx_stbc;
	bool rx_stbc;
	bool su_bfr;
	bool su_bfe;
	bool mu_bfr;
	bool mu_bfe;
	bool txopps;
	bool htc_vht_cap;
} VHTCaps;
#endif


typedef struct { /* Used by: questd.c, dslstats.c|h */
	bool exists;
	char macaddr[24];
	char wdev[8];
} Sta;





typedef struct jiffy_counts_t { /* Used by questd.c, questd.h, dumper.c, dumper.h */
	unsigned long long usr, nic, sys, idle;
	unsigned long long iowait, irq, softirq, steal;
	unsigned long long total;
	unsigned long long busy;
} jiffy_counts_t;

void recalc_sleep_time(bool calc, int toms);
void init_db_hw_config(void);
void get_jif_val(jiffy_counts_t *p_jif);

#endif /* QUESTD */

