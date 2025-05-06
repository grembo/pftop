/* $Id: pftop.c,v 1.91 2007/11/07 06:33:14 canacar Exp $	 */
/*
 * Copyright (c) 2001, 2007 Can Erkin Acar
 * Copyright (c) 2001 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#ifdef HAVE_ALTQ
#include <net/altq/altq.h>
#include <net/altq/altq_cbq.h>
#include <net/altq/altq_priq.h>
#include <net/altq/altq_hfsc.h>
#include <net/altq/altq_fairq.h>
#include <net/altq/altq_codel.h>
#endif

#include <ctype.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <libpfctl.h>

#include "engine.h"
#include "cache.h"
#include "sf-gencode.h"


#define MIN_NUM_STATES 1024
#define NUM_STATE_INC  1024

#define DEFAULT_CACHE_SIZE 10000

/* XXX must also check type before use */
#define PT_ADDR(x) (&(x)->addr.v.a.addr)

/* XXX must also check type before use */
#define PT_MASK(x) (&(x)->addr.v.a.mask)

#define PT_NOROUTE(x) ((x)->addr.type == PF_ADDR_NOROUTE)

/* view management */
int select_states(void);
int read_states(void);
void sort_states(void);
void print_states(void);

int select_rules(void);
int read_rules(void);
void print_rules(void);

int print_header(void);
int keyboard_callback(int ch);

#ifdef HAVE_ALTQ
int select_queues(void);
int read_queues(void);
void print_queues(void);
#endif

/* qsort callbacks */
int sort_size_callback(const void *s1, const void *s2);
int sort_exp_callback(const void *s1, const void *s2);
int sort_pkt_callback(const void *s1, const void *s2);
int sort_age_callback(const void *s1, const void *s2);
int sort_sa_callback(const void *s1, const void *s2);
int sort_sp_callback(const void *s1, const void *s2);
int sort_da_callback(const void *s1, const void *s2);
int sort_dp_callback(const void *s1, const void *s2);
int sort_rate_callback(const void *s1, const void *s2);
int sort_peak_callback(const void *s1, const void *s2);
int pf_dev = -1;

struct sc_ent **state_cache = NULL;
pf_state_t *state_buf = NULL;
int state_buf_len = 0;
u_int32_t *state_ord = NULL;
u_int32_t num_states = 0;
u_int32_t num_states_all = 0;
u_int32_t num_rules = 0;
u_int32_t num_queues = 0;
int cachestates = 0;

struct bpf_program filter_prog;
char *filter_string = NULL;
int dumpfilter = 0;

#define MIN_LABEL_SIZE 5
#define ANCHOR_FLD_SIZE 12

/* Define fields */
field_def fields[] = {
	{"SRC", 20, 45, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"DEST", 20, 45, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"GW", 20, 45, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"STATE", 5, 23, 18, FLD_ALIGN_COLUMN, -1, 0, 0, 0},
	{"AGE", 5, 9, 4, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"EXP", 5, 9, 4, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"PR ", 4, 9, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"DIR", 1, 3, 2, FLD_ALIGN_CENTER, -1, 0, 0, 0},
	{"PKTS", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"BYTES", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"RULE", 2, 4, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"LABEL", MIN_LABEL_SIZE, MIN_LABEL_SIZE, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"STATES", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"EVAL", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"ACTION", 1, 8, 4, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"LOG", 1, 3, 2, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"QUICK", 1, 1, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"KS", 1, 1, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"IF", 4, 6, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"INFO", 40, 80, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"MAX", 3, 5, 2, FLD_ALIGN_RIGHT, -1, 0, FLD_FLAG_HIDDEN, 0},
	{"RATE", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"AVG", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"PEAK", 5, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"ANCHOR", 6, 16, 1, FLD_ALIGN_LEFT, -1, 0, FLD_FLAG_HIDDEN, 0},
	{"QUEUE", 15, 30, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"BW", 4, 5, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"SCH", 3, 4, 1, FLD_ALIGN_LEFT, -1, 0, 0, 0},
	{"PRIO", 1, 4, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"DROP_P", 6, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"DROP_B", 6, 8, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"QLEN", 4, 4, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"BORROW", 4, 6, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"SUSPENDS", 4, 6, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"P/S", 3, 7, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0},
	{"B/S", 4, 7, 1, FLD_ALIGN_RIGHT, -1, 0, 0, 0}
};


#define FIELD_ADDR(x) (&fields[x])

/* for states */
#define FLD_SRC     FIELD_ADDR(0)
#define FLD_DEST    FIELD_ADDR(1)
#define FLD_GW      FIELD_ADDR(2)
#define FLD_STATE   FIELD_ADDR(3)
#define FLD_AGE     FIELD_ADDR(4)
#define FLD_EXP     FIELD_ADDR(5)
/* common */
#define FLD_PROTO   FIELD_ADDR(6)
#define FLD_DIR     FIELD_ADDR(7)
#define FLD_PKTS    FIELD_ADDR(8)
#define FLD_BYTES   FIELD_ADDR(9)
#define FLD_RULE    FIELD_ADDR(10)
/* for rules */
#define FLD_LABEL   FIELD_ADDR(11)
#define FLD_STATS   FIELD_ADDR(12)
#define FLD_EVAL    FIELD_ADDR(13)
#define FLD_ACTION  FIELD_ADDR(14)
#define FLD_LOG     FIELD_ADDR(15)
#define FLD_QUICK   FIELD_ADDR(16)
#define FLD_KST     FIELD_ADDR(17)
#define FLD_IF      FIELD_ADDR(18)
#define FLD_RINFO   FIELD_ADDR(19)
#define FLD_STMAX   FIELD_ADDR(20)
/* other */
#define FLD_SI      FIELD_ADDR(21)    /* instantaneous speed */
#define FLD_SA      FIELD_ADDR(22)    /* average speed */
#define FLD_SP      FIELD_ADDR(23)    /* peak speed */
#define FLD_ANCHOR  FIELD_ADDR(24)
/* for queues */
#define FLD_QUEUE   FIELD_ADDR(25)
#define FLD_BANDW   FIELD_ADDR(26)
#define FLD_SCHED   FIELD_ADDR(27)
#define FLD_PRIO    FIELD_ADDR(28)
#define FLD_DROPP   FIELD_ADDR(29)
#define FLD_DROPB   FIELD_ADDR(30)
#define FLD_QLEN    FIELD_ADDR(31)
#define FLD_BORR    FIELD_ADDR(32)
#define FLD_SUSP    FIELD_ADDR(33)
#define FLD_PKTSPS  FIELD_ADDR(34)
#define FLD_BYTESPS FIELD_ADDR(35)

/* Define views */
field_def *view0[] = {
	FLD_PROTO, FLD_DIR, FLD_SRC, FLD_DEST, FLD_STATE,
	FLD_AGE, FLD_EXP, FLD_PKTS, FLD_BYTES, NULL
};

field_def *view1[] = {
	FLD_PROTO, FLD_DIR, FLD_SRC, FLD_DEST, FLD_GW, FLD_STATE, FLD_AGE,
	FLD_EXP, FLD_PKTS, FLD_BYTES, FLD_SI, FLD_SP, FLD_SA, FLD_RULE, NULL
};

field_def *view2[] = {
	FLD_PROTO, FLD_DIR, FLD_SRC, FLD_DEST, FLD_STATE, FLD_AGE, FLD_EXP,
	FLD_PKTS, FLD_BYTES, FLD_SI, FLD_SP, FLD_SA, FLD_RULE, FLD_GW, NULL
};

field_def *view3[] = {
	FLD_PROTO, FLD_DIR, FLD_SRC, FLD_DEST, FLD_AGE, FLD_EXP, FLD_PKTS,
	FLD_BYTES, FLD_STATE, FLD_SI, FLD_SP, FLD_SA, FLD_RULE, FLD_GW, NULL
};

field_def *view4[] = {
	FLD_PROTO, FLD_DIR, FLD_SRC, FLD_DEST, FLD_PKTS, FLD_BYTES, FLD_STATE,
	FLD_AGE, FLD_EXP, FLD_SI, FLD_SP, FLD_SA, FLD_RULE, FLD_GW, NULL
};

field_def *view5[] = {
	FLD_RULE, FLD_ANCHOR, FLD_ACTION, FLD_DIR, FLD_LOG, FLD_QUICK, FLD_IF,
	FLD_PROTO, FLD_KST, FLD_PKTS, FLD_BYTES, FLD_STATS, FLD_STMAX,
	FLD_RINFO, NULL
};

field_def *view6[] = {
	FLD_RULE, FLD_LABEL, FLD_PKTS, FLD_BYTES, FLD_STATS, FLD_STMAX,
	FLD_ACTION, FLD_DIR, FLD_LOG, FLD_QUICK, FLD_IF, FLD_PROTO,
	FLD_ANCHOR, FLD_KST, NULL
};

field_def *view7[] = {
	FLD_PROTO, FLD_DIR, FLD_SRC, FLD_DEST,  FLD_SI, FLD_SP, FLD_SA,
	FLD_BYTES, FLD_STATE, FLD_PKTS, FLD_AGE, FLD_EXP, FLD_RULE, FLD_GW, NULL
};

field_def *view8[] = {
	FLD_QUEUE, FLD_BANDW, FLD_SCHED, FLD_PRIO, FLD_PKTS, FLD_BYTES,
	FLD_DROPP, FLD_DROPB, FLD_QLEN, FLD_BORR, FLD_SUSP, FLD_PKTSPS,
	FLD_BYTESPS, NULL
};

/* Define orderings */
order_type order_list[] = {
	{"none", "none", 'N', NULL},
	{"bytes", "bytes", 'B', sort_size_callback},
	{"expiry", "exp", 'E', sort_exp_callback},
	{"packets", "pkt", 'P', sort_pkt_callback},
	{"age", "age", 'A', sort_age_callback},
	{"source addr", "src", 'F', sort_sa_callback},
	{"dest. addr", "dest", 'T', sort_da_callback},
	{"source port", "sport", 'S', sort_sp_callback},
	{"dest. port", "dport", 'D', sort_dp_callback},
	{"rate", "rate", 'R', sort_rate_callback},
	{"peak", "peak", 'K', sort_peak_callback},
	{NULL, NULL, 0, NULL}
};

/* Define view managers */
struct view_manager state_mgr = {
	"State", select_states, read_states, sort_states, print_header,
	print_states, keyboard_callback, order_list, NULL
};

struct view_manager rule_mgr = {
	"Rule", select_rules, read_rules, NULL, print_header,
	print_rules, keyboard_callback, NULL, NULL
};

#ifdef HAVE_ALTQ
struct view_manager queue_mgr = {
	"Queue", select_queues, read_queues, NULL, print_header,
	print_queues, keyboard_callback, NULL, NULL
};
#endif

field_view views[] = {
	{view0, "default", '0', &state_mgr},
	{view1, "long", '1', &state_mgr},
	{view2, "state", '2', &state_mgr},
	{view3, "time", '3', &state_mgr},
	{view4, "size", '4', &state_mgr},
	{view5, "rules", '5', &rule_mgr},
	{view6, "label", '6', &rule_mgr},
	{view7, "speed", '7', &state_mgr},
#ifdef HAVE_ALTQ
	{view8, "queue", '8', &queue_mgr},
#endif
	{NULL, NULL, 0, NULL}
};


/* altq structures from pfctl */

#ifdef HAVE_ALTQ
union class_stats {
	class_stats_t		cbq_stats;
	struct priq_classstats	priq_stats;
	struct hfsc_classstats	hfsc_stats;
	struct fairq_classstats	fairq_stats;
	struct codel_ifstats	codel_stats;
};

struct queue_stats {
	union class_stats	 data;
	struct timeval		 timestamp;
	u_int8_t		 valid;
};

struct pf_altq_node {
	struct pf_altq		 altq;
	struct pf_altq_node	*next;
	struct pf_altq_node	*children;
	struct pf_altq_node	*next_flat;
	struct queue_stats	 qstats;
	struct queue_stats	 qstats_last;
	u_int8_t		 depth;
	u_int8_t		 visited;
};
#endif /* HAVE_ALTQ */


/* command prompt */

void cmd_filter(void);
void cmd_delay(void);
void cmd_count(void);

struct command cm_filter = {"Filter", cmd_filter};
struct command cm_delay = {"Seconds to delay", cmd_delay};
struct command cm_count = {"Number of lines to display", cmd_count};

/* ordering functions */

int
sort_size_callback(const void *s1, const void *s2)
{
	u_int64_t b1 = (state_buf[* (u_int32_t *) s1].bytes[0]) + 
		(state_buf[* (u_int32_t *) s1].bytes[1]);
	u_int64_t b2 = (state_buf[* (u_int32_t *) s2].bytes[0]) + 
		(state_buf[* (u_int32_t *) s2].bytes[1]);
	if (b2 > b1)
		return sortdir;
	if (b2 < b1)
		return -sortdir;
	return 0;
}

int
sort_pkt_callback(const void *s1, const void *s2)
{
	u_int64_t p1 = (state_buf[* (u_int32_t *) s1].packets[0]) + 
		(state_buf[* (u_int32_t *) s1].packets[1]);
	u_int64_t p2 = (state_buf[* (u_int32_t *) s2].packets[0]) + 
		(state_buf[* (u_int32_t *) s2].packets[1]);
	if (p2 > p1)
		return sortdir;
	if (p2 < p1)
		return -sortdir;
	return 0;
}

int
sort_age_callback(const void *s1, const void *s2)
{
	if (state_buf[* (u_int32_t *) s2].creation >
	    state_buf[* (u_int32_t *) s1].creation)
		return sortdir;
	if (state_buf[* (u_int32_t *) s2].creation <
	    state_buf[* (u_int32_t *) s1].creation)
		return -sortdir;
	return 0;
}

int
sort_exp_callback(const void *s1, const void *s2)
{
	if (state_buf[* (u_int32_t *) s2].expire >
	    state_buf[* (u_int32_t *) s1].expire)
		return sortdir;
	if (state_buf[* (u_int32_t *) s2].expire <
	    state_buf[* (u_int32_t *) s1].expire)
		return -sortdir;
	return 0;
}

int
sort_rate_callback(const void *s1, const void *s2)
{
	struct sc_ent *e1 = state_cache[* (u_int32_t *) s1];
	struct sc_ent *e2 = state_cache[* (u_int32_t *) s2];

	if (e1 == NULL)
		return sortdir;
	if (e2 == NULL)
		return -sortdir;
	
	if (e2->rate > e1 -> rate)
		return sortdir;
	if (e2->rate < e1 -> rate)
		return -sortdir;
	return 0;
}

int
sort_peak_callback(const void *s1, const void *s2)
{
	struct sc_ent *e1 = state_cache[* (u_int32_t *) s1];
	struct sc_ent *e2 = state_cache[* (u_int32_t *) s2];

	if (e2 == NULL)
		return -sortdir;
	if (e1 == NULL || e2 == NULL)
		return 0;
	
	if (e2->peak > e1 -> peak)
		return sortdir;
	if (e2->peak < e1 -> peak)
		return -sortdir;
	return 0;
}

int
compare_addr(int af, const struct pf_addr *a, const struct pf_addr *b)
{
	switch (af) {
	case AF_INET:
		if (ntohl(a->addr32[0]) > ntohl(b->addr32[0]))
			return 1;
		if (a->addr32[0] != b->addr32[0])
			return -1;
		break;
	case AF_INET6:
		if (ntohl(a->addr32[0]) > ntohl(b->addr32[0]))
			return 1;
		if (a->addr32[0] != b->addr32[0])
			return -1;
		if (ntohl(a->addr32[1]) > ntohl(b->addr32[1]))
			return 1;
		if (a->addr32[1] != b->addr32[1])
			return -1;
		if (ntohl(a->addr32[2]) > ntohl(b->addr32[2]))
			return 1;
		if (a->addr32[2] != b->addr32[2])
			return -1;
		if (ntohl(a->addr32[3]) > ntohl(b->addr32[3]))
			return 1;
		if (a->addr32[3] != b->addr32[3])
			return -1;
		break;
	}
	
	return 0;
}

#ifdef __GNUC__
__inline__
#endif
int
sort_addr_callback(const pf_state_t *s1,
		   const pf_state_t *s2, int dir)
{
	const struct pf_addr *aa, *ab;
	u_int16_t pa, pb;
	int af, ret, ii, io;

	af = s1->key[PF_SK_STACK].af;


	if (af > s2->key[PF_SK_STACK].af)
		return sortdir;
	if (af < s2->key[PF_SK_STACK].af)
		return -sortdir;
	
       	ii = io = 0;

	if (dir == PF_OUT)	/* looking for source addr */
		io = 1;
	else			/* looking for dest addr */
		ii = 1;
	
	if (s1->direction == PF_IN) {
		aa = &s1->key[PF_SK_STACK].addr[ii];
		pa =  s1->key[PF_SK_STACK].port[ii];
	} else {
		aa = &s1->key[PF_SK_WIRE].addr[io];
		pa =  s1->key[PF_SK_WIRE].port[io];
	}

	if (s2->direction == PF_IN) {
		ab = &s2->key[PF_SK_STACK].addr[ii];;
		pb =  s2->key[PF_SK_STACK].port[ii];
	} else {
		ab = &s2->key[PF_SK_WIRE].addr[io];;
		pb =  s2->key[PF_SK_WIRE].port[io];
	}

	ret = compare_addr(af, aa, ab);
	if (ret)
		return ret * sortdir;

	if (ntohs(pa) > ntohs(pb))
		return sortdir;
	return -sortdir;
}

#ifdef __GNUC__
__inline__
#endif
int
sort_port_callback(const pf_state_t *s1,
		   const pf_state_t *s2, int dir)
{
	const struct pf_addr *aa, *ab;
	u_int16_t pa, pb;
	int af, ret, ii, io;

	af = s1->key[PF_SK_STACK].af;


	if (af > s2->key[PF_SK_STACK].af)
		return sortdir;
	if (af < s2->key[PF_SK_STACK].af)
		return -sortdir;
	
       	ii = io = 0;

	if (dir == PF_OUT)	/* looking for source addr */
		io = 1;
	else			/* looking for dest addr */
		ii = 1;
	
	if (s1->direction == PF_IN) {
		aa = &s1->key[PF_SK_STACK].addr[ii];
		pa =  s1->key[PF_SK_STACK].port[ii];
	} else {
		aa = &s1->key[PF_SK_WIRE].addr[io];
		pa =  s1->key[PF_SK_WIRE].port[io];
	}

	if (s2->direction == PF_IN) {
		ab = &s2->key[PF_SK_STACK].addr[ii];;
		pb =  s2->key[PF_SK_STACK].port[ii];
	} else {
		ab = &s2->key[PF_SK_WIRE].addr[io];;
		pb =  s2->key[PF_SK_WIRE].port[io];
	}


	if (ntohs(pa) > ntohs(pb))
		return sortdir;
	if (ntohs(pa) < ntohs(pb))
		return - sortdir;

	ret = compare_addr(af, aa, ab);
	if (ret)
		return ret * sortdir;
	return -sortdir;
}

int sort_sa_callback(const void *p1, const void *p2)
{
	pf_state_t *s1 = state_buf + (* (u_int32_t *) p1);
	pf_state_t *s2 = state_buf + (* (u_int32_t *) p2);
	return sort_addr_callback(s1, s2, PF_OUT);
}

int sort_da_callback(const void *p1, const void *p2)
{
	pf_state_t *s1 = state_buf + (* (u_int32_t *) p1);
	pf_state_t *s2 = state_buf + (* (u_int32_t *) p2);
	return sort_addr_callback(s1, s2, PF_IN);
}

int
sort_sp_callback(const void *p1, const void *p2)
{
	pf_state_t *s1 = state_buf + (* (u_int32_t *) p1);
	pf_state_t *s2 = state_buf + (* (u_int32_t *) p2);
	return sort_port_callback(s1, s2, PF_OUT);
}

int
sort_dp_callback(const void *p1, const void *p2)
{
	pf_state_t *s1 = state_buf + (* (u_int32_t *) p1);
	pf_state_t *s2 = state_buf + (* (u_int32_t *) p2);
	return sort_port_callback(s1, s2, PF_IN);
}

void
sort_states(void)
{
	order_type *ordering;

	if (curr_mgr == NULL)
		return;

	ordering = curr_mgr->order_curr;

	if (ordering == NULL)
		return;
	if (ordering->func == NULL)
		return;
	if (state_buf == NULL)
		return;
	if (num_states <= 0)
		return;

	mergesort(state_ord, num_states, sizeof(u_int32_t), ordering->func);
}

/* state management functions */

void
alloc_buf(int ns)
{
	int len;
	int old_len = state_buf_len;

	if (ns < MIN_NUM_STATES)
		ns = MIN_NUM_STATES;

	len = ns;

	if (len >= state_buf_len) {
		len += NUM_STATE_INC;
		state_buf = realloc(state_buf, len * sizeof(pf_state_t));
		state_ord = realloc(state_ord, len * sizeof(u_int32_t));
		state_cache = realloc(state_cache, 
				      len * sizeof(struct sc_ent *));
		if (state_buf == NULL || state_ord == NULL ||
		    state_cache == NULL)
			err(1, "realloc");
		state_buf_len = len;
		for (int i = old_len; i < len; i++) {
			bzero(&state_buf[i], sizeof(pf_state_t));
			state_ord[i] = 0;
			state_cache[i] = 0;
		}
	}
}

int
select_states(void)
{
	num_disp = num_states;
	return (0);
}

int
read_states(void)
{
	struct pfctl_states ps = { };
	pf_state_t *i, *d;
	int n;

	if (pfctl_get_states(pf_dev, &ps)) {
			msgprintf("Error Reading States (DIOCGETSTATES): %s",
				    strerror(errno));
			return (-1);
	}

	n = 0;
	TAILQ_FOREACH(i, &ps.states, entry) {
		n++;
	}

	if ((state_buf_len * sizeof(pf_state_t)) < (sizeof(struct pfctl_state) * n))
		alloc_buf(n);
	num_states_all = n;

	d = state_buf;
	TAILQ_FOREACH(i, &ps.states, entry) {
		memcpy(d, i, sizeof(*i));
		d++;
	}

	if (dumpfilter) {
		int fd = open("state.dmp", O_WRONLY|O_CREAT|O_EXCL, 0);
		if (fd > 0) {
			write(fd, state_buf, num_states_all * sizeof(pf_state_t));
			close(fd);
		}
	}

	if (filter_prog.bf_insns == NULL) {
		num_states =  num_states_all;
		for (n = 0; n<num_states_all; n++)
			state_ord[n] = n;
	} else {
		num_states = 0;
		for (n = 0; n<num_states_all; n++)
			if (bpf_filter(filter_prog.bf_insns, (const unsigned char *)(&state_buf[n]),
			    sizeof(pf_state_t), sizeof(pf_state_t)) > 0)
				state_ord[num_states++] = n;
	}

	if (cachestates) {
		for (n = 0; n < num_states; n++)
			state_cache[n] = cache_state(state_buf + n);
		cache_endupdate();
	}

	pfctl_free_states(&ps);

	num_disp = num_states;
	return 0;
}

int
unmask(struct pf_addr * m, u_int8_t af)
{
	int i = 31, j = 0, b = 0, msize;
	u_int32_t tmp;

	if (af == AF_INET)
		msize = 1;
	else
		msize = 4;
	while (j < msize && m->addr32[j] == 0xffffffff) {
		b += 32;
		j++;
	}
	if (j < msize) {
		tmp = ntohl(m->addr32[j]);
		for (i = 31; tmp & (1 << i); --i)
			b++;
	}
	return (b);
}

/* display functions */

int
print_header(void)
{
	struct pfctl_status *status;
	struct tm *tp;
	time_t t;
	order_type *ordering;

	int start = dispstart + 1;
	int end = dispstart + maxprint;

	if ((status = pfctl_get_status(pf_dev)) == NULL) {
		msgprintf("Error Reading status (DIOCGETSTATUS): %s", strerror(errno));
		return (-1);
	}
	
	if (end > num_disp)
		end = num_disp;

	tb_start();
	tbprintf("pfTop: ");

	tbprintf(status->running ? "Up" : "Down");

	tbprintf(" %s", curr_mgr ? curr_mgr->name : "???");

	if (num_disp == 0)
		tbprintf(" no entries");
	else
		tbprintf(" %u-%u/%u", start, end, num_disp);

	if (filter_prog.bf_insns != NULL)
		tbprintf(" (%u)", num_states_all);
	
	if (curr_view) {
		tbprintf(", View: %s", curr_view->name);
	}
	
	if (curr_mgr && curr_mgr->sort_fn != NULL) {
		ordering = curr_mgr->order_curr;
		if (ordering != NULL) {
			tbprintf(", Order: %s", ordering->name);
			if (sortdir < 0 && ordering->func != NULL)
				tbprintf(" (rev)");
		}
	}
	if (cachestates)
		tbprintf(", Cache: %d", cache_max);

	if (paused)
		tbprintf(" PAUSED");

	if (rawmode)
		printf("\n\n%s\n", tmp_buf);
	else
		mvprintw(0, 0, "%s", tmp_buf);

	time(&t);
	tp = localtime(&t);
	if (tp) {
		int len;

		tb_start();
		tbprintf("%.2u:%.2u:%.2u", tp->tm_hour,
			 tp->tm_min, tp->tm_sec);
		len = columns - strlen(tmp_buf);
		if (len < 0)
			len = 0;
		mvprintw(0, len, "%s", tmp_buf);
	}

	tb_end();

	pfctl_free_status(status);

	return (1);
}

void
tb_print_addr(struct pf_addr * addr, struct pf_addr * mask, int af)
{
	static char buf[48];
	const char *bf;

	bf = inet_ntop(af, addr, buf, sizeof(buf));
	tbprintf("%s", bf);

	if (mask != NULL) {
		if (!PF_AZERO(mask, af))
			tbprintf("/%u", unmask(mask, af));
	}
}

void
print_fld_host2(field_def *fld, struct pfctl_state_key *ks,
		struct pfctl_state_key *kn, int idx, int af)
{
	struct pf_addr *as = &ks->addr[idx];
	struct pf_addr *an = &kn->addr[idx];

	u_int16_t ps = ntohs(ks->port[idx]);
	u_int16_t pn = ntohs(kn->port[idx]);

	if (fld == NULL)
		return;

	if (fld->width < 3) {
		print_fld_str(fld, "*");
		return;
	}

	tb_start();
	tb_print_addr(as, NULL, af);

	if (af == AF_INET)
		tbprintf(":%u", ps);
	else
		tbprintf("[%u]", ps);

	print_fld_tb(fld);

	if (PF_ANEQ(as, an, af) || ps != pn) {
		tb_start();
		tb_print_addr(an, NULL, af);

		if (af == AF_INET)
			tbprintf(":%u", pn);
		else
			tbprintf("[%u]", pn);
		print_fld_tb(FLD_GW);
	}

}

void
print_fld_state(field_def *fld, unsigned int proto,
		unsigned int s1, unsigned int s2)
{
	int len;
	
	if (fld == NULL)
		return;

	len = fld->width;
	if (len < 1)
		return;
	
	tb_start();

	if (proto == IPPROTO_TCP) {
		if (s1 <= TCPS_TIME_WAIT && s2 <= TCPS_TIME_WAIT)
			tbprintf("%s:%s", tcpstates[s1], tcpstates[s2]);
#ifdef PF_TCPS_PROXY_SRC
		else if (s1 == PF_TCPS_PROXY_SRC ||
			   s2 == PF_TCPS_PROXY_SRC)
			tbprintf("PROXY:SRC\n");
		else if (s1 == PF_TCPS_PROXY_DST ||
			 s2 == PF_TCPS_PROXY_DST)
			tbprintf("PROXY:DST\n");
#endif
		else
			tbprintf("<BAD STATE LEVELS>");
	} else if (proto == IPPROTO_UDP && s1 < PFUDPS_NSTATES &&
		   s2 < PFUDPS_NSTATES) {
		const char *states[] = PFUDPS_NAMES;
		tbprintf("%s:%s", states[s1], states[s2]);
	} else if (proto != IPPROTO_ICMP && s1 < PFOTHERS_NSTATES &&
		   s2 < PFOTHERS_NSTATES) {
		/* XXX ICMP doesn't really have state levels */
		const char *states[] = PFOTHERS_NAMES;
		tbprintf("%s:%s", states[s1], states[s2]);
	} else {
		tbprintf("%u:%u", s1, s2);
	}

	if (strlen(tmp_buf) > len) {
		tb_start();
		tbprintf("%u:%u", s1, s2);
	}

	print_fld_tb(fld);
}

int
print_state(pf_state_t * s, struct sc_ent * ent)
{
	pf_state_peer_t *src, *dst;
	struct protoent *p;

	if (s->direction == PF_OUT) {
		src = &s->src;
		dst = &s->dst;
	} else {
		src = &s->dst;
		dst = &s->src;
	}

	p = getprotobynumber(s->key[PF_SK_WIRE].proto);

	if (p != NULL)
		print_fld_str(FLD_PROTO, p->p_name);
	else
		print_fld_uint(FLD_PROTO, s->key[PF_SK_WIRE].proto);

	if (s->direction == PF_OUT) {
		print_fld_host2(FLD_SRC, &s->key[PF_SK_WIRE],
		    &s->key[PF_SK_STACK], 1, s->key[PF_SK_WIRE].af);
		print_fld_host2(FLD_DEST, &s->key[PF_SK_WIRE],
		    &s->key[PF_SK_STACK], 0, s->key[PF_SK_WIRE].af);
	} else {
		print_fld_host2(FLD_SRC, &s->key[PF_SK_STACK],
		    &s->key[PF_SK_WIRE], 0, s->key[PF_SK_STACK].af);
		print_fld_host2(FLD_DEST, &s->key[PF_SK_STACK],
		    &s->key[PF_SK_WIRE], 1, s->key[PF_SK_STACK].af);
	}

	if (s->direction == PF_OUT)
		print_fld_str(FLD_DIR, "Out");
	else
		print_fld_str(FLD_DIR, "In");

	print_fld_state(FLD_STATE, s->key[PF_SK_WIRE].proto, src->state, dst->state);
	print_fld_age(FLD_AGE, s->creation);
	print_fld_age(FLD_EXP, s->expire);
	{
		u_int64_t sz = (s->bytes[0]) + (s->bytes[1]);

		print_fld_size(FLD_PKTS, (s->packets[0]) +
			       (s->packets[1]));
		print_fld_size(FLD_BYTES, sz);
		print_fld_rate(FLD_SA, (s->creation) ?
			       ((double)sz/s->creation) : -1);
	}
	print_fld_uint(FLD_RULE, s->rule);
	if (cachestates && ent != NULL) {
		print_fld_rate(FLD_SI, ent->rate);
		print_fld_rate(FLD_SP, ent->peak);
	}

	end_line();
	return 1;
}

void
print_states(void)
{
	int n, count = 0;

	for (n = dispstart; n < num_disp; n++) {
		count += print_state(state_buf + state_ord[n],
				     state_cache[state_ord[n]]);
		if (maxprint > 0 && count >= maxprint)
			break;
	}
}

/* rule display */

struct pfctl_rule *rules = NULL;
u_int32_t alloc_rules = 0;

int
select_rules(void)
{
	num_disp = num_rules;
	return (0);
}


void
add_rule_alloc(u_int32_t nr)
{
	if (nr == 0)
		return;

	num_rules += nr;

	if (rules == NULL) {
		rules = malloc(num_rules * sizeof(struct pf_rule));
		if (rules == NULL)
			err(1, "malloc");
		alloc_rules = num_rules;
	} else if (num_rules > alloc_rules) {
		rules = realloc(rules, num_rules * sizeof(struct pf_rule));
		if (rules == NULL)
			err(1, "realloc");
		alloc_rules = num_rules;
	}
}

int label_length;

int
read_anchor_rules(char *anchor)
{
	struct pfioc_rule pr;
	struct pfctl_rule rule;
	u_int32_t nr, num, off;

	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
	if (ioctl(pf_dev, DIOCGETRULES, &pr)) {
		msgprintf("Error Reading Anchor %s (DIOCGETRULES): %s",
			  *anchor ? anchor : "/", strerror(errno));
		return (-1);
	}

	off = num_rules;
	num = pr.nr;
	add_rule_alloc(num);

	for (nr = 0; nr < num; ++nr) {
		if (pfctl_get_rule(pf_dev, nr, pr.ticket, anchor, pr.action, &rule, pr.anchor_call)) {
			msgprintf("Error Reading Rule (DIOCGETRULE): %s",
				  strerror(errno));
			return (-1);
		}
		/* XXX overload pr.anchor, to store a pointer to
		 * anchor name */
		rule.anchor = (struct pfctl_anchor *) anchor;
		{
			int len = strlen(rule.label[0]);
			if (len > label_length)
				label_length = len;
		}
		rules[off + nr] = rule;
	}

	return (num);
}

struct anchor_name {
	char name[MAXPATHLEN];
	struct anchor_name *next;
	u_int32_t ref;
};

struct anchor_name *anchor_root = NULL;
struct anchor_name *anchor_end = NULL;
struct anchor_name *anchor_free = NULL;

struct anchor_name*
alloc_anchor_name(const char *path)
{
	struct anchor_name *a;

	a = anchor_free;
	if (a == NULL) {
		a = (struct anchor_name *)malloc(sizeof(struct anchor_name));
		if (a == NULL)
			return (NULL);
	} else
		anchor_free = a->next;

	if (anchor_root == NULL)
		anchor_end = a;

	a->next = anchor_root;
	anchor_root = a;

	a->ref = 0;
	strlcpy(a->name, path, sizeof(a->name));
	return (a);
}

void
reset_anchor_names(void)
{
	if (anchor_end == NULL)
		return;

	anchor_end->next = anchor_free;
	anchor_free = anchor_root;
	anchor_root = anchor_end = NULL;
}

struct pfioc_ruleset ruleset;
char *rs_end = NULL;

int
read_rulesets(const char *path)
{
	char *pre;
	struct anchor_name *a;
	u_int32_t nr, ns;
	int len;

	if (path == NULL)
		ruleset.path[0] = '\0';
	else if (strlcpy(ruleset.path, path, sizeof(ruleset.path)) >= 
	    sizeof(ruleset.path))
		 return (-1);

	/* a persistent storage for anchor names */
	a = alloc_anchor_name(ruleset.path);
	if (a == NULL)
		return (-1);

	len = read_anchor_rules(a->name);
	if (len < 0)
		return (-1);

	a->ref += len;

	if (ioctl(pf_dev, DIOCGETRULESETS, &ruleset)) {
		msgprintf("Error Reading Rulesets (DIOCGETRULESETS): %s",
			  strerror(errno));
		return (-1);
	}

	ns = ruleset.nr;

	if (rs_end == NULL)
		rs_end = ruleset.path + sizeof(ruleset.path);

	/* 'pre' tracks the previous level on the anchor */
	pre = strchr(ruleset.path, 0);
	len = rs_end - pre;
	if (len < 1)
		return (-1);
	--len;

	for (nr = 0; nr < ns; ++nr) {
		ruleset.nr = nr;
		if (ioctl(pf_dev, DIOCGETRULESET, &ruleset)) {
			msgprintf("Error Reading Ruleset (DIOCGETRULESET): %s",
				    strerror(errno));
			return (-1);
		}
		*pre = '/';
		if (strlcpy(pre + 1, ruleset.name, len) < len)
			read_rulesets(ruleset.path);
		*pre = '\0';
	}

	return (0);
}

void
compute_anchor_field(void)
{
	struct anchor_name *a;
	int sum, cnt, mx, nx;
	sum = cnt = mx = 0;

	for (a = anchor_root; a != NULL; a = a->next, cnt++) {
		int len;
		if (a->ref == 0)
			continue;
		len = strlen(a->name);
		sum += len;
		if (len > mx)
			mx = len;
	}

	nx = sum/cnt;
	if (nx < ANCHOR_FLD_SIZE)
		nx = (mx < ANCHOR_FLD_SIZE) ? mx : ANCHOR_FLD_SIZE;

	if (FLD_ANCHOR->max_width != mx ||
	    FLD_ANCHOR->norm_width != nx) {
		FLD_ANCHOR->max_width = mx;
		FLD_ANCHOR->norm_width = nx;
		field_setup();
		need_update = 1;
	}
}

int
read_rules(void)
{
	int ret;
	num_rules = 0;

	label_length = MIN_LABEL_SIZE;

	reset_anchor_names();
	ret = read_rulesets(NULL);
	compute_anchor_field();

	{
		int nw, mw;
		nw = mw = label_length;
		if (nw > 16)
			nw = 16;

		if (FLD_LABEL->norm_width != nw || 
		    FLD_LABEL->max_width != mw) {
			FLD_LABEL->norm_width = nw;
			FLD_LABEL->max_width = mw;
			field_setup();
			need_update = 1;
		}
	}

	num_disp = num_rules;
	return (ret);
}

void
tb_print_addrw(struct pf_addr_wrap *addr, struct pf_addr *mask, u_int8_t af)
{
	switch (addr->type) {
	case PF_ADDR_ADDRMASK:
		tb_print_addr(&addr->v.a.addr, mask, af);
		break;
	case  PF_ADDR_NOROUTE:
		tbprintf("noroute");
		break;
	case PF_ADDR_DYNIFTL:
		tbprintf("(%s)", addr->v.ifname);
		break;
	case PF_ADDR_TABLE:
		tbprintf("<%s>", addr->v.tblname);
		break;
	default:
		tbprintf("UNKNOWN");
		break;
	}
}

void
tb_print_op(u_int8_t op, const char *a1, const char *a2)
{
	if (op == PF_OP_IRG)
		tbprintf("%s >< %s ", a1, a2);
	else if (op == PF_OP_XRG)
		tbprintf("%s <> %s ", a1, a2);
	else if (op == PF_OP_RRG)
		tbprintf("%s:%s ", a1, a2);
	else if (op == PF_OP_EQ)
		tbprintf("= %s ", a1);
	else if (op == PF_OP_NE)
		tbprintf("!= %s ", a1);
	else if (op == PF_OP_LT)
		tbprintf("< %s ", a1);
	else if (op == PF_OP_LE)
		tbprintf("<= %s ", a1);
	else if (op == PF_OP_GT)
		tbprintf("> %s ", a1);
	else if (op == PF_OP_GE)
		tbprintf(">= %s ", a1);
}

void
tb_print_port(u_int8_t op, u_int16_t p1, u_int16_t p2, char *proto)
{
	char a1[6], a2[6];
	struct servent *s = getservbyport(p1, proto);

	p1 = ntohs(p1);
	p2 = ntohs(p2);
	snprintf(a1, sizeof(a1), "%u", p1);
	snprintf(a2, sizeof(a2), "%u", p2);
	tbprintf("port ");
	if (s != NULL && (op == PF_OP_EQ || op == PF_OP_NE))
		tb_print_op(op, s->s_name, a2);
	else
		tb_print_op(op, a1, a2);
}

void
tb_print_fromto(struct pf_rule_addr *src, struct pf_rule_addr *dst,
		u_int8_t af, u_int8_t proto)
{
	if (
	    PF_AZERO(PT_ADDR(src), AF_INET6) &&
	    PF_AZERO(PT_ADDR(dst), AF_INET6) &&
	    ! PT_NOROUTE(src) && ! PT_NOROUTE(dst) &&
	    PF_AZERO(PT_MASK(src), AF_INET6) &&
	    PF_AZERO(PT_MASK(dst), AF_INET6) &&
	    !src->port_op && !dst->port_op)
		tbprintf("all ");
	else {
		tbprintf("from ");
		if (PT_NOROUTE(src))
			tbprintf("no-route ");
		else if (PF_AZERO(PT_ADDR(src), AF_INET6) &&
			 PF_AZERO(PT_MASK(src), AF_INET6))
			tbprintf("any ");
		else {
			if (src->neg)
				tbprintf("! ");
			tb_print_addrw(&src->addr, PT_MASK(src), af);
			tbprintf(" ");
		}
		if (src->port_op)
			tb_print_port(src->port_op, src->port[0],
				      src->port[1],
				      proto == IPPROTO_TCP ? "tcp" : "udp");
		
		tbprintf("to ");
		if (PT_NOROUTE(dst))
			tbprintf("no-route ");
		else if (PF_AZERO(PT_ADDR(dst), AF_INET6) &&
			 PF_AZERO(PT_MASK(dst), AF_INET6))
			tbprintf("any ");
		else {
			if (dst->neg)
				tbprintf("! ");
			tb_print_addrw(&dst->addr, PT_MASK(dst), af);
			tbprintf(" ");
		}
		if (dst->port_op)
			tb_print_port(dst->port_op, dst->port[0],
				      dst->port[1],
				      proto == IPPROTO_TCP ? "tcp" : "udp");
	}
}

void
tb_print_ugid(u_int8_t op, unsigned u1, unsigned u2,
	      const char *t, unsigned umax)
{
	char	a1[11], a2[11];

	snprintf(a1, sizeof(a1), "%u", u1);
	snprintf(a2, sizeof(a2), "%u", u2);

	tbprintf("%s ", t);
	if (u1 == umax && (op == PF_OP_EQ || op == PF_OP_NE))
		tb_print_op(op, "unknown", a2);
	else
		tb_print_op(op, a1, a2);
}

void
tb_print_flags(u_int8_t f)
{
	const char *tcpflags = "FSRPAUEW";
	int i;

	for (i = 0; tcpflags[i]; ++i)
		if (f & (1 << i))
			tbprintf("%c", tcpflags[i]);
}

void
print_rule(struct pfctl_rule *pr)
{
	static const char *actiontypes[] = { "Pass", "Block", "Scrub", "Nat",
	    "no Nat", "Binat", "no Binat", "Rdr", "no Rdr" };
	int numact = sizeof(actiontypes) / sizeof(char *);

	static const char *routetypes[] = { "", "fastroute", "route-to",
	    "dup-to", "reply-to" };

	int numroute = sizeof(routetypes) / sizeof(char *);

	if (pr == NULL) return;

	print_fld_str(FLD_LABEL, pr->label[0]);
	print_fld_size(FLD_STATS, pr->states_tot);

	print_fld_size(FLD_PKTS, pr->packets[0] + pr->packets[1]);
	print_fld_size(FLD_BYTES, pr->bytes[0] + pr->bytes[1]);
	print_fld_uint(FLD_RULE, pr->nr);
	if (pr->direction == PF_IN)
		print_fld_str(FLD_DIR, "In");
	else if (pr->direction == PF_OUT)
		print_fld_str(FLD_DIR, "Out");
	else
		print_fld_str(FLD_DIR, "Any");

	if (pr->quick)
		print_fld_str(FLD_QUICK, "Quick");

	if (pr->keep_state == PF_STATE_NORMAL)
		print_fld_str(FLD_KST, "Keep");
	else if (pr->keep_state == PF_STATE_MODULATE)
		print_fld_str(FLD_KST, "Mod");
#ifdef PF_STATE_SYNPROXY
	else if (pr->keep_state == PF_STATE_MODULATE)
		print_fld_str(FLD_KST, "Syn");
#endif
	if (pr->log == 1)
		print_fld_str(FLD_LOG, "Log");
	else if (pr->log == 2)
		print_fld_str(FLD_LOG, "All");

	if (pr->action >= numact)
		print_fld_uint(FLD_ACTION, pr->action);
	else print_fld_str(FLD_ACTION, actiontypes[pr->action]);

	if (pr->proto) {
		struct protoent *p = getprotobynumber(pr->proto);

		if (p != NULL)
			print_fld_str(FLD_PROTO, p->p_name);
		else
			print_fld_uint(FLD_PROTO, pr->proto);
	}

	if (pr->ifname[0]) {
		tb_start();
		if (pr->ifnot)
			tbprintf("!");
		tbprintf("%s", pr->ifname);
		print_fld_tb(FLD_IF);
	}
	if (pr->max_states)
		print_fld_uint(FLD_STMAX, pr->max_states);
	/* print info field */

	tb_start();

	if (pr->natpass)
		tbprintf("pass ");
	if (pr->action == PF_DROP) {
		if (pr->rule_flag & PFRULE_RETURNRST)
			tbprintf("return-rst ");
#ifdef PFRULE_RETURN
		else if (pr->rule_flag & PFRULE_RETURN)
			tbprintf("return ");
#endif
#ifdef PFRULE_RETURNICMP
		else if (pr->rule_flag & PFRULE_RETURNICMP)
			tbprintf("return-icmp ");
#endif
		else
			tbprintf("drop ");
	}

	if (pr->rt > 0 && pr->rt < numroute) {
		tbprintf("%s ", routetypes[pr->rt]);
		if (pr->rt != PF_FASTROUTE)
			tbprintf("... ");
	}

	if (pr->af) {
		if (pr->af == AF_INET)
			tbprintf("inet ");
		else
			tbprintf("inet6 ");
	}

	tb_print_fromto(&pr->src, &pr->dst, pr->af, pr->proto);
	if (pr->uid.op)
		tb_print_ugid(pr->uid.op, pr->uid.uid[0], pr->uid.uid[1],
		        "user", UINT_MAX);
	if (pr->gid.op)
		tb_print_ugid(pr->gid.op, pr->gid.gid[0], pr->gid.gid[1],
		        "group", UINT_MAX);

	if (pr->flags || pr->flagset) {
		tbprintf(" flags ");
		tb_print_flags(pr->flags);
		tbprintf("/");
		tb_print_flags(pr->flagset);
	}

	tbprintf(" ");

	if (pr->tos)
		tbprintf("tos 0x%2.2x ", pr->tos);
#ifdef PFRULE_FRAGMENT
	if (pr->rule_flag & PFRULE_FRAGMENT)
		tbprintf("fragment ");
#endif
#ifdef PFRULE_NODF
	if (pr->rule_flag & PFRULE_NODF)
		tbprintf("no-df ");
#endif
#ifdef PFRULE_RANDOMID
	if (pr->rule_flag & PFRULE_RANDOMID)
		tbprintf("random-id ");
#endif
	if (pr->min_ttl)
		tbprintf("min-ttl %d ", pr->min_ttl);
	if (pr->max_mss)
		tbprintf("max-mss %d ", pr->max_mss);
	if (pr->allow_opts)
		tbprintf("allow-opts ");

	if (pr->action == PF_SCRUB) {
#ifdef PFRULE_REASSEMBLE_TCP
		if (pr->rule_flag & PFRULE_REASSEMBLE_TCP)
			tbprintf("reassemble tcp ");
#endif
#ifdef PFRULE_FRAGDROP
		if (pr->rule_flag & PFRULE_FRAGDROP)
			tbprintf("fragment drop-ovl ");
		else
#endif
#ifdef PFRULE_FRAGCROP
		if (pr->rule_flag & PFRULE_FRAGCROP)
			tbprintf("fragment crop ");
		else
#endif
			tbprintf("fragment reassemble ");
	}

#ifdef HAVE_ALTQ	
	if (pr->qname[0] && pr->pqname[0])
		tbprintf("queue(%s, %s) ", pr->qname, pr->pqname);
	else if (pr->qname[0])
		tbprintf("queue %s ", pr->qname);
#endif
	if (pr->tagname[0])
		tbprintf("tag %s ", pr->tagname);
	if (pr->match_tagname[0]) {
		if (pr->match_tag_not)
			tbprintf("! ");
		tbprintf("tagged %s ", pr->match_tagname);
	}
	print_fld_tb(FLD_RINFO);

	/* XXX anchor field overloaded with anchor name */
	print_fld_str(FLD_ANCHOR, (char *)pr->anchor);
	end_line();
}

void
print_rules(void)
{
	u_int32_t n, count = 0;
	
	for (n = dispstart; n < num_rules; n++) {
		print_rule(rules + n);
		count ++;
		if (maxprint > 0 && count >= maxprint)
			break;
	}
}

/* queue display */

#ifdef HAVE_ALTQ

struct pf_altq_node *
pfctl_find_altq_node(struct pf_altq_node *root, const char *qname,
    const char *ifname)
{
	struct pf_altq_node	*node, *child;

	for (node = root; node != NULL; node = node->next) {
		if (!strcmp(node->altq.qname, qname)
		    && !(strcmp(node->altq.ifname, ifname)))
			return (node);
		if (node->children != NULL) {
			child = pfctl_find_altq_node(node->children, qname,
			    ifname);
			if (child != NULL)
				return (child);
		}
	}
	return (NULL);
}

void
pfctl_insert_altq_node(struct pf_altq_node **root,
    const struct pf_altq altq, const struct queue_stats qstats)
{
	struct pf_altq_node	*node;

	node = calloc(1, sizeof(struct pf_altq_node));
	if (node == NULL)
		err(1, "pfctl_insert_altq_node: calloc");
	memcpy(&node->altq, &altq, sizeof(struct pf_altq));
	memcpy(&node->qstats, &qstats, sizeof(qstats));
	node->next = node->children = node->next_flat = NULL;
	node->depth = 0;
	node->visited = 1;

	if (*root == NULL)
		*root = node;
	else if (!altq.parent[0]) {
		struct pf_altq_node	*prev = *root;

		while (prev->next != NULL)
			prev = prev->next;
		prev->next = node;
	} else {
		struct pf_altq_node	*parent;

		parent = pfctl_find_altq_node(*root, altq.parent, altq.ifname);
		if (parent == NULL)
			errx(1, "parent %s not found", altq.parent);
		node->depth = parent->depth+1;
		if (parent->children == NULL)
			parent->children = node;
		else {
			struct pf_altq_node *prev = parent->children;

			while (prev->next != NULL)
				prev = prev->next;
			prev->next = node;
		}
	}
}

void
pfctl_set_next_flat(struct pf_altq_node *node, struct pf_altq_node *up)
{
	while (node) {
		struct pf_altq_node *next = node->next ? node->next : up;
		if (node->children) {
			node->next_flat = node->children;
			pfctl_set_next_flat(node->children, next);
		} else
			node->next_flat = next;
		node = node->next;
	}
}

int
pfctl_update_qstats(struct pf_altq_node **root, int *inserts)
{
	struct pf_altq_node	*node;
	struct pfioc_altq	 pa;
	struct pfioc_qstats	 pq;
	u_int32_t		 nr;
	struct queue_stats	 qstats;
	u_int32_t		 nr_queues;
	int			 ret = 0;

	*inserts = 0;
	memset(&pa, 0, sizeof(pa));
	memset(&pq, 0, sizeof(pq));
	memset(&qstats, 0, sizeof(qstats));
	if (ioctl(pf_dev, DIOCGETALTQS, &pa)) {
		msgprintf("Error Reading Queues (DIOCGETALTQS): %s",
			  strerror(errno));
		return (-1);
	}

	num_queues = nr_queues = pa.nr;
	if (pa.altq.scheduler == ALTQT_CODEL)
		num_queues = 1;
	for (nr = 0; nr < nr_queues; ++nr) {
		pa.nr = nr;
		if (ioctl(pf_dev, DIOCGETALTQ, &pa)) {
			msgprintf("Error Reading Queue (DIOCGETALTQ): %s",
				  strerror(errno));
			ret = -1;
			break;
		}
#ifdef PFALTQ_FLAG_IF_REMOVED
		if ((pa.altq.qid > 0 || pa.altq.scheduler == ALTQT_CODEL) &&
		    !(pa.altq.local_flags & PFALTQ_FLAG_IF_REMOVED)) {
#else
		if (pa.altq.qid > 0  || pa.altq.scheduler == ALTQT_CODEL) {
#endif
			pq.nr = nr;
			pq.ticket = pa.ticket;
			pq.buf = &qstats;
			pq.nbytes = sizeof(qstats);
			if (ioctl(pf_dev, DIOCGETQSTATS, &pq)) {
				msgprintf("Error Reading Queue (DIOCGETQSTATS): %s",
					  strerror(errno));
				ret = -1;
				break;
			}
			qstats.valid = 1;
			gettimeofday(&qstats.timestamp, NULL);
			if ((node = pfctl_find_altq_node(*root, pa.altq.qname,
			    pa.altq.ifname)) != NULL) {
				// update altq data too as bandwidth may have changed
				memcpy(&node->altq, &pa.altq, sizeof(struct pf_altq));
				memcpy(&node->qstats_last, &node->qstats,
				    sizeof(struct queue_stats));
				memcpy(&node->qstats, &qstats,
				    sizeof(qstats));
				node->visited = 1;
			} else {
				pfctl_insert_altq_node(root, pa.altq, qstats);
				*inserts = 1;
			}
		}
		else
			--num_queues;
	}

	pfctl_set_next_flat(*root, NULL);

	return (ret);
}

void
pfctl_free_altq_node(struct pf_altq_node *node)
{
	while (node != NULL) {
		struct pf_altq_node	*prev;

		if (node->children != NULL)
			pfctl_free_altq_node(node->children);
		prev = node;
		node = node->next;
		free(prev);
	}
}

void
pfctl_mark_all_unvisited(struct pf_altq_node *root)
{
 	if (root != NULL) {
		struct pf_altq_node	*node = root;
		while (node != NULL) {
		        node->visited = 0;
		        node = node->next_flat;
		}
	}
}

int
pfctl_have_unvisited(struct pf_altq_node *root)
{
 	if (root == NULL)
 		return(0);
 	else {
		struct pf_altq_node	*node = root;
		while (node != NULL) {
		        if (node->visited == 0)
		        	return(1);
			node = node->next_flat;
		}
		return(0);
	}
}

struct pf_altq_node	*altq_root = NULL;

int
select_queues(void)
{
	num_disp = num_queues;
	return (0);
}

int
read_queues(void)
{
	static int first_read = 1;
	int inserts;
	num_disp = num_queues = 0;
	
	pfctl_mark_all_unvisited(altq_root);
	if (pfctl_update_qstats(&altq_root, &inserts))
		return (-1);
	
	// Allow inserts only on first read;
	// on subsequent reads clear and reload
	if (first_read == 0 &&
	    (inserts != 0 || pfctl_have_unvisited(altq_root) != 0)) {
		pfctl_free_altq_node(altq_root);
		altq_root = NULL;
		first_read = 1;
		if (pfctl_update_qstats(&altq_root, &inserts))
			return (-1);
	}
	
	first_read = 0;
	num_disp = num_queues;
	
	return(0);
}

double
calc_interval(struct timeval *cur_time, struct timeval *last_time)
{
	double	sec;

	sec = (double)(cur_time->tv_sec - last_time->tv_sec) +
	    (double)(cur_time->tv_usec - last_time->tv_usec) / 1000000;

	return (sec);
}

double
calc_rate(u_int64_t new_bytes, u_int64_t last_bytes, double interval)
{
	double	rate;

	rate = (double)(new_bytes - last_bytes) / interval;
	return (rate);
}

double
calc_pps(u_int64_t new_pkts, u_int64_t last_pkts, double interval)
{
	double	pps;

	pps = (double)(new_pkts - last_pkts) / interval;
	return (pps);
}

#define DEFAULT_PRIORITY	1

void
print_queue(struct pf_altq_node *node)
{
	u_int8_t d;
	double	interval, pps, bps;
	pps = bps = 0;

	tb_start();
	for (d = 0; d < node->depth; d++)
		tbprintf(" ");
	if (node->altq.qname[0] != '\0')
		tbprintf(node->altq.qname);
	else
		tbprintf("root");
	print_fld_tb(FLD_QUEUE);

	if (node->altq.scheduler == ALTQT_CBQ ||
	    node->altq.scheduler == ALTQT_HFSC || node->altq.scheduler == ALTQT_FAIRQ || node->altq.scheduler == ALTQT_CODEL
		)
		print_fld_bw(FLD_BANDW, (double)node->altq.bandwidth);
	
	if (node->altq.priority != DEFAULT_PRIORITY)
		print_fld_uint(FLD_PRIO,
			       node->altq.priority);
	
	if (node->qstats.valid && node->qstats_last.valid)
		interval = calc_interval(&node->qstats.timestamp,
					 &node->qstats_last.timestamp);
	else
		interval = 0;

	switch (node->altq.scheduler) {
	case ALTQT_CBQ:
		print_fld_str(FLD_SCHED, "cbq");
		print_fld_size(FLD_PKTS,
			       node->qstats.data.cbq_stats.xmit_cnt.packets);
		print_fld_size(FLD_BYTES,
			       node->qstats.data.cbq_stats.xmit_cnt.bytes);
		print_fld_size(FLD_DROPP,
			       node->qstats.data.cbq_stats.drop_cnt.packets);
		print_fld_size(FLD_DROPB,
			       node->qstats.data.cbq_stats.drop_cnt.bytes);
		print_fld_size(FLD_QLEN, node->qstats.data.cbq_stats.qcnt);
		print_fld_size(FLD_BORR, node->qstats.data.cbq_stats.borrows);
		print_fld_size(FLD_SUSP, node->qstats.data.cbq_stats.delays);
		if (interval > 0) {
			pps = calc_pps(node->qstats.data.cbq_stats.xmit_cnt.packets,
				       node->qstats_last.data.cbq_stats.xmit_cnt.packets, interval);
			bps = calc_rate(node->qstats.data.cbq_stats.xmit_cnt.bytes,
					node->qstats_last.data.cbq_stats.xmit_cnt.bytes, interval);
		}
		break;
	case ALTQT_PRIQ:
		print_fld_str(FLD_SCHED, "priq");
		print_fld_size(FLD_PKTS,
			       node->qstats.data.priq_stats.xmitcnt.packets);
		print_fld_size(FLD_BYTES,
			       node->qstats.data.priq_stats.xmitcnt.bytes);
		print_fld_size(FLD_DROPP,
			       node->qstats.data.priq_stats.dropcnt.packets);
		print_fld_size(FLD_DROPB,
			       node->qstats.data.priq_stats.dropcnt.bytes);
		print_fld_size(FLD_QLEN, node->qstats.data.priq_stats.qlength);
		if (interval > 0) {
			pps = calc_pps(node->qstats.data.priq_stats.xmitcnt.packets,
				       node->qstats_last.data.priq_stats.xmitcnt.packets, interval);
			bps = calc_rate(node->qstats.data.priq_stats.xmitcnt.bytes,
					node->qstats_last.data.priq_stats.xmitcnt.bytes, interval);
		}
		break;
	case ALTQT_HFSC:
		print_fld_str(FLD_SCHED, "hfsc");
		print_fld_size(FLD_PKTS,
				node->qstats.data.hfsc_stats.xmit_cnt.packets);
		print_fld_size(FLD_BYTES,
				node->qstats.data.hfsc_stats.xmit_cnt.bytes);
		print_fld_size(FLD_DROPP,
				node->qstats.data.hfsc_stats.drop_cnt.packets);
		print_fld_size(FLD_DROPB,
				node->qstats.data.hfsc_stats.drop_cnt.bytes);
		print_fld_size(FLD_QLEN, node->qstats.data.hfsc_stats.qlength);
		if (interval > 0) {
			pps = calc_pps(node->qstats.data.hfsc_stats.xmit_cnt.packets,
					node->qstats_last.data.hfsc_stats.xmit_cnt.packets, interval);
			bps = calc_rate(node->qstats.data.hfsc_stats.xmit_cnt.bytes,
					node->qstats_last.data.hfsc_stats.xmit_cnt.bytes, interval);
		}
		break;
       case ALTQT_FAIRQ:
               print_fld_str(FLD_SCHED, "fairq");
               print_fld_size(FLD_PKTS,
                               node->qstats.data.fairq_stats.xmit_cnt.packets);
               print_fld_size(FLD_BYTES,
                               node->qstats.data.fairq_stats.xmit_cnt.bytes);
               print_fld_size(FLD_DROPP,
                               node->qstats.data.fairq_stats.drop_cnt.packets);
               print_fld_size(FLD_DROPB,
                               node->qstats.data.fairq_stats.drop_cnt.bytes);
               print_fld_size(FLD_QLEN, node->qstats.data.fairq_stats.qlength);
               if (interval > 0) {
                       pps = calc_pps(node->qstats.data.fairq_stats.xmit_cnt.packets,
                                       node->qstats_last.data.fairq_stats.xmit_cnt.packets, interval);
                       bps = calc_rate(node->qstats.data.fairq_stats.xmit_cnt.bytes,
                                       node->qstats_last.data.fairq_stats.xmit_cnt.bytes, interval);
               }
               break;
       case ALTQT_CODEL:
               print_fld_str(FLD_SCHED, "codel");
               print_fld_size(FLD_PKTS,
                               node->qstats.data.codel_stats.cl_xmitcnt.packets);
               print_fld_size(FLD_BYTES,
                               node->qstats.data.codel_stats.cl_xmitcnt.bytes);
               print_fld_size(FLD_DROPP,
                               node->qstats.data.codel_stats.cl_dropcnt.packets);
               print_fld_size(FLD_DROPB,
                               node->qstats.data.codel_stats.cl_dropcnt.bytes);
               print_fld_size(FLD_QLEN, node->qstats.data.codel_stats.qlength);
               if (interval > 0) {
                       pps = calc_pps(node->qstats.data.codel_stats.cl_xmitcnt.packets,
                                       node->qstats_last.data.codel_stats.cl_xmitcnt.packets, interval);
                       bps = calc_rate(node->qstats.data.codel_stats.cl_xmitcnt.bytes,
                                       node->qstats_last.data.codel_stats.cl_xmitcnt.bytes, interval);
               }
               break;
	}

	/* if (node->altq.scheduler != ALTQT_HFSC && interval > 0) { */
	if (node->altq.scheduler && interval > 0) {
		tb_start();
		if (pps > 0 && pps < 1)
			tbprintf("%-3.1lf", pps);
		else
			tbprintf("%u", (unsigned int) pps);
		
		print_fld_tb(FLD_PKTSPS);
		print_fld_bw(FLD_BYTESPS, bps);
	}
}

void
print_queues(void)
{
	u_int32_t n, count = 0;
	struct pf_altq_node *node = altq_root;

	for (n = 0; n < dispstart; n++)
		node = node->next_flat;

	for (; n < num_disp; n++) {
		print_queue(node);
		node = node->next_flat;
		end_line();
		count ++;
		if (maxprint > 0 && count >= maxprint)
			break;
	}
}

#endif /* HAVE_ALTQ */

/* main program functions */

void
update_cache()
{
	static int pstate = -1;
	if (pstate == cachestates)
		return;

	pstate = cachestates;
	if (cachestates) {
		show_field(FLD_SI);
		show_field(FLD_SP);
		gotsig_alarm = 1;
	} else {
		hide_field(FLD_SI);
		hide_field(FLD_SP);
		need_update = 1;
	}
	field_setup();
}

void
usage()
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-abhir] [-c cache] [-d cnt]", __progname);
	fprintf(stderr, " [-o field] [-s time] [-v view] [-w width] [num]\n");
	exit(1);
}

void
show_help(void)
{
	int line = 0;

	if (rawmode)
		return;

	erase();
	mvprintw(line, 2, "pfTop Help");
	line += 2;
	mvprintw(line,    5, " c  - toggle state Cache");
	mvprintw(line++, 40, " f  - set state Filter");
	mvprintw(line,    5, " h  - Help (this page)");
	mvprintw(line++, 40, " n  - set Number of lines");
	mvprintw(line,    5, " o  - next sort Order");
	mvprintw(line++, 40, " p  - Pause display");
	mvprintw(line,    5, " r  - Reverse sort order");
	mvprintw(line++, 40, " s  - Set update interval");
	mvprintw(line,    5, " v  - next View");
	mvprintw(line++, 40, " q  - Quit");
	line++;
	mvprintw(line++, 5, "0-8 - select view directly");
	mvprintw(line++, 5, "SPC - update immediately");
	mvprintw(line++, 5, "^L  - refresh display");
	mvprintw(line++, 5, "^G  - clear command entry line");
	line++;
	mvprintw(line++, 5, "cursor keys - scroll display");
	line++;
	mvprintw(line++, 3, "Sorting shortcuts:");
	line++;
	mvprintw(line,    5, " A  - Age");
	mvprintw(line,   25, " B  - Bytes");
	mvprintw(line++, 45, " D  - Dest. port");
	mvprintw(line,    5, " E  - Expiry");
	mvprintw(line,   25, " F  - From");
	mvprintw(line++, 45, " N  - None ");
	mvprintw(line,    5, " P  - Packets");
	mvprintw(line,   25, " S  - Src. port");
	mvprintw(line++, 45, " T  - To");
	mvprintw(line,    5, " R  - Rate");
	mvprintw(line,   25, " K  - peaK");
	line++;
	line++;
	mvprintw(line++, 6, "press any key to continue ...");

	while (getch() == ERR);

}


void
cmd_filter(void)
{
	struct bpf_program p;

	if (*cmdbuf == '\0') {
		sf_freecode(&filter_prog);
		free(filter_string);
		filter_string = NULL;
		return;
	}

	if (sf_compile(&p, cmdbuf, 1, 0)) {
		msgprintf("Error: %s", sf_get_error());
		return;
	}

	if (filter_prog.bf_insns != NULL)
		sf_freecode(&filter_prog);

	filter_prog = p;
	free(filter_string);
	filter_string = strdup(cmdbuf);
}

void
cmd_delay(void)
{
	int del;
	del = atoi(cmdbuf);
	if (del > 0) {
		delay = del;
		gotsig_alarm = 1;
	}
}


void
cmd_count(void)
{
	int ms;
	ms = atoi(cmdbuf);

	if (ms <= 0 || ms > lines - HEADER_LINES)
		maxprint = lines - HEADER_LINES;
	else
		maxprint = ms;
}


int
keyboard_callback(int ch)
{
	switch (ch) {
	case 'c':
		cachestates = !cachestates;
		update_cache();
		break;
	case 'f':
		command_set(&cm_filter, filter_string);
		break;
	case '?':
		/* FALLTHROUGH */
	case 'h':
		show_help();
		need_update = 1;
		break;
	case 'n':
		command_set(&cm_count, NULL);
		break;
	case 's':
		command_set(&cm_delay, NULL);
		break;
	default:
		return 0;
	};

	return 1;
}

void
initialize(void)
{
	field_view *v;
	engine_initialize();

	v = views;
	while(v->name != NULL)
		add_view(v++);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;

	struct pfctl_status *status = NULL;

	char *orderstr = NULL;
	char *viewstr = NULL;
	char *filterstr = NULL;

	int cachesize = DEFAULT_CACHE_SIZE;
	int countmax = 0;
	int maxstates = 0;

	int ch;

	while ((ch = getopt(argc, argv, "abDhirc:s:d:f:o:v:w:S:")) != -1) {
		switch (ch) {
		case 'a':
			maxstates = -1;
			break;
		case 'c':
			cachesize = atoi(optarg);
			if (cachesize < 0)
				cachesize = 0;
			break;
		case 'D':
			dumpfilter = 1;
			break;
		case 'd':
			countmax = atoi(optarg);
			if (countmax < 0)
				countmax = 0;
			break;
		case 'i':
			interactive = 1;
			break;
		case 'b':
			rawmode = 1;
			interactive = 0;
			break;
		case 'f':
			filterstr = optarg;
			break;
		case 'o':
			orderstr = optarg;
			break;
		case 'r':
			sortdir *= -1;
			break;
		case 'S':
			dispstart = atoi(optarg);
			if (dispstart < 0)
				dispstart = 0;
			break;
		case 's':
			delay = atoi(optarg);
			if (delay < 1)
				delay = 1;
			break;
		case 'v':
			viewstr = optarg;
			break;
		case 'w':
			rawwidth = atoi(optarg);
			if (rawwidth < 1)
				rawwidth = DEFAULT_WIDTH;
			if (rawwidth >= MAX_LINE_BUF)
				rawwidth = MAX_LINE_BUF - 1;
			break;
		case 'h':
			/* FALLTHROUGH */
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		maxstates = atoi(argv[0]);
	else if (argc > 1)
		usage();

	if (filterstr) {

		if (sf_compile(&filter_prog, filterstr, 1, 0)) {
			fprintf(stderr, "Filter error: %s\n", sf_get_error());
			return 1;
		}
		filter_string = strdup(filterstr);
		if (dumpfilter) {
			bpf_dump(&filter_prog, 0);
			rawmode = 1;
			interactive = 0;
		}
	}

	initialize();

	set_order(orderstr);
	set_view(viewstr);

	if (!isatty(STDOUT_FILENO)) {
		rawmode = 1;
		interactive = 0;
	}

	pf_dev = open("/dev/pf", O_RDONLY);
	if (pf_dev == -1)
		err(1, "open(\"/dev/pf\")");

	/* preallocate existing states if possible */
	if ((status = pfctl_get_status(pf_dev)) == NULL) {
		warn("DIOCGETSTATUS");
		alloc_buf(0);
	} else {
		alloc_buf(status->states);
		pfctl_free_status(status);
		status = NULL;
	}


	setup_term(maxstates);

	/* initialize cache with given size */
	if (cache_init(cachesize))
		errx(1, "Failed to initialize cache.");

	/* initialize version dependent fields */
	show_field(FLD_STMAX);
	show_field(FLD_ANCHOR);

	if (interactive && cachesize > 0)
		cachestates = 1;
	update_cache();

	if (rawmode && countmax == 0)
		countmax = 1;

	gotsig_alarm = 1;

	engine_loop(countmax);

	close(pf_dev);
	return 0;
}
