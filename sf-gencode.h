/*	$OpenBSD: gencode.h,v 1.14 2007/01/02 18:31:21 reyk Exp $	*/
/*	$Id: sf-gencode.h,v 1.4 2007/10/01 20:40:24 canacar Exp $	*/

/*
 * Copyright (c) 2007 Can Erkin Acar <canacar@gmail.com>
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @(#) $Header: /var/cvsroot/pftop/sf-gencode.h,v 1.4 2007/10/01 20:40:24 canacar Exp $ (LBL)
 */

#ifndef _SF_GENCODE_H_
#define _SF_GENCODE_H_

#include <pcap/pcap.h>

/* Address qualifiers. */
#define Q_HOST		1
#define Q_NET		2
#define Q_PORT		3
#define Q_PROTO		5

/* Protocol qualifiers. */

#define Q_IP		1
#define Q_TCP		2
#define Q_UDP		3
#define Q_ICMP		4

#define Q_IPV6		5
#define Q_AH		6
#define Q_ESP		7
#define Q_CARP		8
#define Q_PFSYNC	9


/* Directional qualifiers. */

#define Q_SRC		1
#define Q_DST		2
#define Q_OR		3
#define Q_AND		4
#define Q_GATEWAY	5

#define Q_DEFAULT	0
#define Q_UNDEF		255

struct slist;

struct stmt {
	int code;
	struct slist *jt;	/*only for relative jump in block*/
	struct slist *jf;	/*only for relative jump in block*/
	bpf_int32 k;
};

struct slist {
	struct stmt s;
	struct slist *next;
};

/* 
 * A bit vector to represent definition sets.  We assume TOT_REGISTERS
 * is smaller than 8*sizeof(atomset).
 */
typedef bpf_u_int32 atomset;
#define ATOMMASK(n) (1 << (n))
#define ATOMELEM(d, n) (d & ATOMMASK(n))

/*
 * An unbounded set.
 */
typedef bpf_u_int32 *uset;

/*
 * Total number of atomic entities, including accumulator (A) and index (X).
 * We treat all these guys similarly during flow analysis.
 */
#define N_ATOMS (BPF_MEMWORDS+2)

struct edge {
	int id;
	int code;
	uset edom;
	struct block *succ;
	struct block *pred;
	struct edge *next;	/* link list of incoming edges for a node */
};

struct block {
	int id;
	struct slist *stmts;	/* side effect stmts */
	struct stmt s;		/* branch stmt */
	int mark;
	int longjt;		/* jt branch requires long jump */
	int longjf;		/* jf branch requires long jump */
	int level;
	int offset;
	int sense;
	struct edge et;
	struct edge ef;
	struct block *head;
	struct block *link;	/* link field used by optimizer */
	uset dom;
	uset closure;
	struct edge *in_edges;
	atomset def, kill;
	atomset in_use;
	atomset out_use;
	int oval;
	int val[N_ATOMS];
};

struct arth {
	struct block *b;	/* protocol checks */
	struct slist *s;	/* stmt list */
	int regno;		/* virtual register number of result */
};

struct qual {
	unsigned char addr;
	unsigned char proto;
	unsigned char dir;
	unsigned char pad;
};

struct arth *gen_loadi(int);
struct arth *gen_loadlen(void);
struct arth *gen_neg(struct arth *);
struct arth *gen_arth(int, struct arth *, struct arth *);

void gen_and(struct block *, struct block *);
void gen_or(struct block *, struct block *);
void gen_not(struct block *);

struct block *gen_scode(const char *, struct qual);
struct block *gen_ecode(const u_char *, struct qual);
struct block *gen_mcode(const char *, const char *, int, struct qual);
struct block *gen_mcode6(const char *, const char *, int, struct qual);
struct block *gen_ncode(const char *, bpf_u_int32, struct qual);
struct block *gen_proto_abbrev(int);
struct block *gen_relation(int, struct arth *, struct arth *, int);
struct block *gen_less(int);
struct block *gen_greater(int);
struct block *gen_byteop(int, int, int);
struct block *gen_inbound(int);

struct block *gen_ifname(char *);
struct block *gen_rnr(int);
struct arth  *gen_loadbytes(int);
struct arth  *gen_loadpackets(int);
struct arth  *gen_loadage(void);
struct arth  *gen_loadexpire(void);

void bpf_optimize(struct block **);
__dead2 void bpf_error(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)));

void finish_parse(struct block *);
char *sdup(const char *);

struct bpf_insn *icode_to_fcode(struct block *, int *);
int pcap_parse(void);
void lex_init(char *);
void sappend(struct slist *, struct slist *);

/* XXX */
#define JT(b)  ((b)->et.succ)
#define JF(b)  ((b)->ef.succ)

__dead2 void sf_error(const char *fmt, ...);
const char *sf_get_error(void);
int sf_compile(struct bpf_program *, char *, int, bpf_u_int32);
void sf_freecode(struct bpf_program *);
void bpf_dump(const struct bpf_program *, int);

extern int no_optimize;

#endif
