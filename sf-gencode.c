/*	$OpenBSD: gencode.c,v 1.28 2007/01/02 18:35:17 reyk Exp $	*/
/*	$Id: sf-gencode.c,v 1.8 2007/10/03 05:52:36 canacar Exp $	*/

/*
 * Copyright (c) 2007 Can Erkin Acar <canacar@gmail.com>
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998
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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>


#include <net/pfvar.h>

#include <netdb.h>
#include <stdlib.h>
#include <stddef.h>
#include <memory.h>
#include <setjmp.h>
#include <stdarg.h>

#define INET6

#include <pcap/pcap.h>
#include <pcap-namedb.h>
#include "sf-gencode.h"
#include "pcap-nametoaddr.h"

#include "config.h"

#define JMP(c) ((c)|BPF_JMP|BPF_K)

/* Locals */
static jmp_buf top_ctx;


#define PFTOP_ERRBUF_SIZE 1024
static char sf_errbuf[PFTOP_ERRBUF_SIZE];

/* VARARGS */
__dead2 void
sf_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(sf_errbuf, PFTOP_ERRBUF_SIZE, fmt, ap);
	va_end(ap);
	longjmp(top_ctx, 1);
	/* NOTREACHED */
}

const char *
sf_get_error(void)
{
	return sf_errbuf;
}

static int alloc_reg(void);
static void free_reg(int);

static struct block *root;

/*
 * We divy out chunks of memory rather than call malloc each time so
 * we don't have to worry about leaking memory.  It's probably
 * not a big deal if all this memory was wasted but it this ever
 * goes into a library that would probably not be a good idea.
 */
#define NCHUNKS 16
#define CHUNK0SIZE 1024
struct chunk {
	u_int n_left;
	void *m;
};

static struct chunk chunks[NCHUNKS];
static int cur_chunk;

static void *newchunk(u_int);
static void freechunks(void);
static __inline struct block *new_block(int);
static __inline struct slist *new_stmt(int);
static struct block *gen_retblk(int);
static __inline void syntax(void);

static void backpatch(struct block *, struct block *);
static void merge(struct block *, struct block *);
static struct block *gen_cmp(u_int, u_int, bpf_int32);
static struct block *gen_mcmp(u_int, u_int, bpf_int32, bpf_u_int32);
#ifdef HAVE_STATE_IFNAME
static struct block *gen_bcmp(u_int, u_int, const u_char *);
#endif
static __inline struct block *gen_proto(int);
static struct block *gen_linktype(int);
static struct block *gen_hostop(bpf_u_int32, bpf_u_int32, int);
static struct block *gen_hostop6(struct in6_addr *, struct in6_addr *, int);
static struct block *gen_host(bpf_u_int32, bpf_u_int32, int, int);
static struct block *gen_host6(struct in6_addr *, struct in6_addr *, int, int);
struct block *gen_portop(int, int, int);
static struct block *gen_port(int, int, int);
static int lookup_proto(const char *, int);
static struct slist *xfer_to_x(struct arth *);
static struct slist *xfer_to_a(struct arth *);
static struct block *gen_len(int, int);

static void *
newchunk(u_int n)
{
	struct chunk *cp;
	int k, size;

	/* XXX Round to structure boundary. */
	n = ALIGN(n);

	cp = &chunks[cur_chunk];
	if (n > cp->n_left) {
		++cp, k = ++cur_chunk;
		if (k >= NCHUNKS)
			sf_error("out of memory");
		size = CHUNK0SIZE << k;
		cp->m = (void *)malloc(size);
		if (cp->m == NULL)
			sf_error("out of memory");
		
		memset((char *)cp->m, 0, size);
		cp->n_left = size;
		if (n > size)
			sf_error("out of memory");
	}
	cp->n_left -= n;
	return (void *)((char *)cp->m + cp->n_left);
}

static void
freechunks()
{
	int i;

	cur_chunk = 0;
	for (i = 0; i < NCHUNKS; ++i)
		if (chunks[i].m != NULL) {
			free(chunks[i].m);
			chunks[i].m = NULL;
		}
}

/*
 * A strdup whose allocations are freed after code generation is over.
 */
char *
sdup(const char *s)
{
	int n = strlen(s) + 1;
	char *cp = newchunk(n);

	strlcpy(cp, s, n);
	return (cp);
}

static __inline struct block *
new_block(int code)
{
	struct block *p;

	p = (struct block *)newchunk(sizeof(*p));
	p->s.code = code;
	p->head = p;

	return (p);
}

static __inline struct slist *
new_stmt(int code)
{
	struct slist *p;

	p = (struct slist *)newchunk(sizeof(*p));
	p->s.code = code;

	return (p);
}

static struct block *
gen_retblk(int v)
{
	struct block *b = new_block(BPF_RET|BPF_K);

	b->s.k = v;
	return (b);
}

static __inline void
syntax(void)
{
	sf_error("syntax error in filter expression");
}


static bpf_u_int32 netmask;
int no_optimize;

/*
 * entry point for using the compiler with no pcap open
 * pass in all the stuff that is needed explicitly instead.
 */
int
sf_compile(struct bpf_program *program,
	      char *buf, int optimize, bpf_u_int32 mask)
{
	extern int n_errors;
	int len;

	n_errors = 0;
	root = NULL;

	if (setjmp(top_ctx)) {
		freechunks();
		return (-1);
	}

	netmask = mask;

	lex_init(buf ? buf : "");

	pcap_parse();

	if (n_errors)
		sf_error("Error compiling filter expression");

	if (root == NULL)
		root = gen_retblk(1);

	if (optimize) {
		bpf_optimize(&root);
		if (root == NULL ||
		    (root->s.code == (BPF_RET|BPF_K) && root->s.k == 0))
			sf_error("expression rejects all packets");
	}

	program->bf_insns = icode_to_fcode(root, &len);
	program->bf_len = len;

	freechunks();
	return (0);
}

/*
 * Clean up a "struct bpf_program" by freeing all the memory allocated
 * in it.
 */
void
sf_freecode(struct bpf_program *program)
{
	program->bf_len = 0;
	if (program->bf_insns != NULL) {
		free((char *)program->bf_insns);
		program->bf_insns = NULL;
	}
}

/*
 * Backpatch the blocks in 'list' to 'target'.  The 'sense' field indicates
 * which of the jt and jf fields has been resolved and which is a pointer
 * back to another unresolved block (or nil).  At least one of the fields
 * in each block is already resolved.
 */
static void
backpatch(struct block *list, struct block *target)
{
	struct block *next;

	while (list) {
		if (!list->sense) {
			next = JT(list);
			JT(list) = target;
		} else {
			next = JF(list);
			JF(list) = target;
		}
		list = next;
	}
}

/*
 * Merge the lists in b0 and b1, using the 'sense' field to indicate
 * which of jt and jf is the link.
 */
static void
merge(struct block *b0, struct block *b1)
{
	struct block **p = &b0;

	/* Find end of list. */
	while (*p)
		p = !((*p)->sense) ? &JT(*p) : &JF(*p);

	/* Concatenate the lists. */
	*p = b1;
}

void
finish_parse(struct block *p)
{
	backpatch(p, gen_retblk(1));
	p->sense = !p->sense;
	backpatch(p, gen_retblk(0));
	root = p->head;
}

void
gen_and(struct block *b0, struct block *b1)
{
	backpatch(b0, b1->head);
	b0->sense = !b0->sense;
	b1->sense = !b1->sense;
	merge(b1, b0);
	b1->sense = !b1->sense;
	b1->head = b0->head;
}

void
gen_or(struct block *b0, struct block *b1)
{
	b0->sense = !b0->sense;
	backpatch(b0, b1->head);
	b0->sense = !b0->sense;
	merge(b1, b0);
	b1->head = b0->head;
}

void
gen_not(struct block *b)
{
	b->sense = !b->sense;
}

static struct block *
gen_cmp(u_int offset, u_int size, bpf_int32 v)
{
	struct slist *s;
	struct block *b;

	s = new_stmt(BPF_LD|BPF_ABS|size);
	s->s.k = offset;

	b = new_block(JMP(BPF_JEQ));
	b->stmts = s;
	b->s.k = v;

	return b;
}

static struct block *
gen_mcmp(u_int offset, u_int size, bpf_int32 v, bpf_u_int32 mask)
{
	struct block *b = gen_cmp(offset, size, v);
	struct slist *s;

	if (mask != 0xffffffff) {
		s = new_stmt(BPF_ALU|BPF_AND|BPF_K);
		s->s.k = mask;
		b->stmts->next = s;
	}
	return b;
}

#ifdef HAVE_STATE_IFNAME
static struct block *
gen_bcmp(u_int offset, u_int size, const u_char *v)
{
	struct block *b, *tmp;

	b = NULL;
	while (size >= 4) {
		const u_char *p = &v[size - 4];
		bpf_int32 w = ((bpf_int32)p[0] << 24) |
		    ((bpf_int32)p[1] << 16) | ((bpf_int32)p[2] << 8) | p[3];

		tmp = gen_cmp(offset + size - 4, BPF_W, w);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
		size -= 4;
	}
	while (size >= 2) {
		const u_char *p = &v[size - 2];
		bpf_int32 w = ((bpf_int32)p[0] << 8) | p[1];

		tmp = gen_cmp(offset + size - 2, BPF_H, w);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
		size -= 2;
	}
	if (size > 0) {
		tmp = gen_cmp(offset, BPF_B, (bpf_int32)v[0]);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
	}
	return b;
}
#endif

static struct block *
gen_linktype(int proto)
{
	if (proto == ETHERTYPE_IP)
		return (gen_cmp(offsetof(pf_state_t, key[PF_SK_WIRE].af), BPF_B,
				(bpf_int32)AF_INET));
	if (proto == ETHERTYPE_IPV6)
		return (gen_cmp(offsetof(pf_state_t, key[PF_SK_WIRE].af), BPF_B,
				(bpf_int32)AF_INET6));
	/* XXX just return false? */
	return gen_cmp(offsetof(pf_state_t, key[PF_SK_WIRE].af), BPF_B, (bpf_int32)proto);
}

static __inline struct block *
gen_proto(int proto)
{
	return (gen_cmp(offsetof(pf_state_t, key[PF_SK_WIRE].proto), BPF_B,
			(bpf_int32)proto));
}

#ifdef HAVE_PFSYNC_KEY
static struct block *
gen_hostop(bpf_u_int32 addr, bpf_u_int32 mask, int dir)
{
	struct block *b0, *b1, *b2, *bi, *bo;
	const static int isrc_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[0].v4);
	const static int osrc_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[1].v4);
	const static int idst_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[1].v4);
	const static int odst_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[0].v4);

	const static int igwy1_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[0].v4);
	const static int ogwy1_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[1].v4);
	const static int igwy2_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[1].v4);
	const static int ogwy2_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[0].v4);

	addr = ntohl(addr);
	mask = ntohl(mask);

	bi = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
	bo = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);

	switch (dir) {

	case Q_SRC:
		b1 = gen_mcmp(osrc_off, BPF_W, addr, mask);
		gen_and(bo, b1);
		b0 = gen_mcmp(isrc_off, BPF_W, addr, mask);
		gen_and(bi, b0);
		gen_or(b0, b1);
		break;

	case Q_DST:
		b1 = gen_mcmp(odst_off, BPF_W, addr, mask);
		gen_and(bo, b1);
		b0 = gen_mcmp(idst_off, BPF_W, addr, mask);
		gen_and(bi, b0);
		gen_or(b0, b1);
		break;

	case Q_GATEWAY:
		/* (in && (addr == igwy1 || addr == igwy2)) ||
		   (out && (addr == ogwy1 || addr == ogwy2))  phew! */
		b1 = gen_mcmp(igwy1_off, BPF_W, addr, mask);
		b0 = gen_mcmp(igwy2_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		gen_and(bi, b1);
		b2 = gen_mcmp(ogwy1_off, BPF_W, addr, mask);
		b0 = gen_mcmp(ogwy2_off, BPF_W, addr, mask);
		gen_or(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_AND:
		b1 = gen_mcmp(isrc_off, BPF_W, addr, mask);
		b0 = gen_mcmp(idst_off, BPF_W, addr, mask);
		gen_and(b0, b1);
		gen_and(bi, b1);
		b2 = gen_mcmp(osrc_off, BPF_W, addr, mask);
		b0 = gen_mcmp(odst_off, BPF_W, addr, mask);
		gen_and(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_OR:
		b1 = gen_mcmp(isrc_off, BPF_W, addr, mask);
		b0 = gen_mcmp(idst_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		gen_and(bi, b1);
		b2 = gen_mcmp(osrc_off, BPF_W, addr, mask);
		b0 = gen_mcmp(odst_off, BPF_W, addr, mask);
		gen_or(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_DEFAULT:
		b1 = gen_mcmp(isrc_off, BPF_W, addr, mask);
		b0 = gen_mcmp(idst_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		b0 = gen_mcmp(osrc_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		b0 = gen_mcmp(odst_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid direcion specifier: %d", dir);
	}

	b0 = gen_linktype(ETHERTYPE_IP);
	gen_and(b0, b1);

	return b1;
}

#else
static struct block *
gen_hostop(bpf_u_int32 addr, bpf_u_int32 mask, int dir)
{
	struct block *b0, *b1, *b2;
	const static int lan_off = offsetof(pf_state_t, lan.addr.v4);
	const static int gwy_off = offsetof(pf_state_t, gwy.addr.v4);
	const static int ext_off = offsetof(pf_state_t, ext.addr.v4);

	addr = ntohl(addr);
	mask = ntohl(mask);

	switch (dir) {

	case Q_SRC:
		/* XXX can be simplified */
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);
		b1 = gen_mcmp(lan_off, BPF_W, addr, mask);
		gen_and(b0, b1);
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
		b2 = gen_mcmp(ext_off, BPF_W, addr, mask);
		gen_and(b0, b2);
		gen_or(b2, b1);
		break;

	case Q_DST:
		/* XXX can be simplified */
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);
		b1 = gen_mcmp(ext_off, BPF_W, addr, mask);
		gen_and(b0, b1);
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
		b2 = gen_mcmp(lan_off, BPF_W, addr, mask);
		gen_and(b0, b2);
		gen_or(b2, b1);
		break;

	case Q_GATEWAY:
		b1 = gen_mcmp(gwy_off, BPF_W, addr, mask);
		break;

	case Q_AND:
		b1 = gen_mcmp(ext_off, BPF_W, addr, mask);
		b0 = gen_mcmp(lan_off, BPF_W, addr, mask);
		gen_and(b0, b1);
		break;

	case Q_OR:
		b1 = gen_mcmp(ext_off, BPF_W, addr, mask);
		b0 = gen_mcmp(lan_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		break;

	case Q_DEFAULT:
		b1 = gen_mcmp(ext_off, BPF_W, addr, mask);
		b0 = gen_mcmp(lan_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		b0 = gen_mcmp(gwy_off, BPF_W, addr, mask);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid direcion specifier: %d", dir);
	}

	b0 = gen_linktype(ETHERTYPE_IP);
	gen_and(b0, b1);

	return b1;
}
#endif

static struct block *
gen_hostcmp6(u_int off, u_int32_t *a, u_int32_t *m)
{
	struct block *b0, *b1;

	/* this order is important */
	b1 = gen_mcmp(off + 12, BPF_W, a[3], m[3]);
	b0 = gen_mcmp(off + 8, BPF_W, a[2], m[2]);
	gen_and(b0, b1);
	b0 = gen_mcmp(off + 4, BPF_W, a[1], m[1]);
	gen_and(b0, b1);
	b0 = gen_mcmp(off + 0, BPF_W, a[0], m[0]);
	gen_and(b0, b1);

	return b1;
}

#ifdef HAVE_PFSYNC_KEY
static struct block *
gen_hostop6(struct in6_addr *addr, struct in6_addr *mask, int dir)

{
	struct block *b0, *b1, *b2, *bi, *bo;
	u_int32_t *a, *m;
	const static int isrc_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[0].v6);
	const static int osrc_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[1].v6);
	const static int idst_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[1].v6);
	const static int odst_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[0].v6);

	const static int igwy1_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[0].v6);
	const static int ogwy1_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[1].v6);
	const static int igwy2_off = offsetof(pf_state_t, key[PF_SK_WIRE].addr[1].v6);
	const static int ogwy2_off = offsetof(pf_state_t, key[PF_SK_STACK].addr[0].v6);

	a = (u_int32_t *)addr;
	m = (u_int32_t *)mask;

	bi = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
	bo = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);

	switch (dir) {

	case Q_SRC:
		b1 = gen_hostcmp6(osrc_off, a, m);
		gen_and(bo, b1);
		b0 = gen_hostcmp6(isrc_off, a, m);
		gen_and(bi, b0);
		gen_or(b0, b1);
		break;

	case Q_DST:
		b1 = gen_hostcmp6(odst_off, a, m);
		gen_and(bo, b1);
		b0 = gen_hostcmp6(idst_off, a, m);
		gen_and(bi, b0);
		gen_or(b0, b1);
		break;

	case Q_GATEWAY:
		/* (in && (addr == igwy1 || addr == igwy2)) ||
		   (out && (addr == ogwy1 || addr == ogwy2))  phew! */
		b1 = gen_hostcmp6(igwy1_off, a, m);
		b0 = gen_hostcmp6(igwy2_off, a, m);
		gen_or(b0, b1);
		gen_and(bi, b1);
		b2 = gen_hostcmp6(ogwy1_off, a, m);
		b0 = gen_hostcmp6(ogwy2_off, a, m);
		gen_or(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_AND:
		b1 = gen_hostcmp6(isrc_off, a, m);
		b0 = gen_hostcmp6(idst_off, a, m);
		gen_and(b0, b1);
		gen_and(bi, b1);
		b2 = gen_hostcmp6(osrc_off, a, m);
		b0 = gen_hostcmp6(odst_off, a, m);
		gen_and(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_OR:
		b1 = gen_hostcmp6(isrc_off, a, m);
		b0 = gen_hostcmp6(idst_off, a, m);
		gen_or(b0, b1);
		gen_and(bi, b1);
		b2 = gen_hostcmp6(osrc_off, a, m);
		b0 = gen_hostcmp6(odst_off, a, m);
		gen_or(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_DEFAULT:
		b1 = gen_hostcmp6(isrc_off, a, m);
		b0 = gen_hostcmp6(idst_off, a, m);
		gen_or(b0, b1);
		b0 = gen_hostcmp6(osrc_off, a, m);
		gen_or(b0, b1);
		b0 = gen_hostcmp6(odst_off, a, m);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid direcion specifier: %d", dir);
	}

	b0 = gen_linktype(ETHERTYPE_IPV6);
	gen_and(b0, b1);

	return b1;
}
#else
static struct block *
gen_hostop6(struct in6_addr *addr, struct in6_addr *mask, int dir)
{
	struct block *b0, *b1, *b2;
	u_int32_t *a, *m;

	const static int lan_off = offsetof(pf_state_t, lan.addr.v6);
	const static int gwy_off = offsetof(pf_state_t, gwy.addr.v6);
	const static int ext_off = offsetof(pf_state_t, ext.addr.v6);
	a = (u_int32_t *)addr;
	m = (u_int32_t *)mask;


	switch (dir) {

	case Q_SRC:
		/* XXX can be simplified */
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);
		b1 = gen_hostcmp6(lan_off, a, m);
		gen_and(b0, b1);
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
		b2 = gen_hostcmp6(ext_off, a, m);
		gen_and(b0, b2);
		gen_or(b2, b1);
		break;

	case Q_DST:
		/* XXX can be simplified */
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);
		b1 = gen_hostcmp6(ext_off, a, m);
		gen_and(b0, b1);
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
		b2 = gen_hostcmp6(lan_off, a, m);
		gen_and(b0, b2);
		gen_or(b2, b1);
		break;

	case Q_GATEWAY:
		b1 = gen_hostcmp6(gwy_off, a, m);
		break;

	case Q_AND:
		b1 = gen_hostcmp6(ext_off, a, m);
		b0 = gen_hostcmp6(lan_off, a, m);
		gen_and(b0, b1);
		break;

	case Q_OR:
		b1 = gen_hostcmp6(ext_off, a, m);
		b0 = gen_hostcmp6(lan_off, a, m);
		gen_or(b0, b1);
		break;

	case Q_DEFAULT:
		b1 = gen_hostcmp6(ext_off, a, m);
		b0 = gen_hostcmp6(lan_off, a, m);
		gen_or(b0, b1);
		b0 = gen_hostcmp6(gwy_off, a, m);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid direcion specifier: %d", dir);
	}


	b0 = gen_linktype(ETHERTYPE_IPV6);
	gen_and(b0, b1);
	return b1;
}
#endif

static const char *
get_modifier_by_id(int id)
{
	switch (id) {

	case Q_DEFAULT:
		return "default";
	case Q_IP:
		return "ip";
	case Q_TCP:
		return "tcp";
	case Q_UDP:
		return "udp";
	case Q_ICMP:
		return "icmp";
	case Q_IPV6:
		return "ip6";
	case Q_AH:
		return "ah";
	case Q_ESP:
		return "esp";
	case Q_PFSYNC:
		return "pfsync";
	case Q_CARP:
		return "carp";
	default:
		return "unknown";
	}
}

static struct block *
gen_host(bpf_u_int32 addr, bpf_u_int32 mask, int proto, int dir)
{
	switch (proto) {
	case Q_DEFAULT:
	case Q_IP:
		return gen_hostop(addr, mask, dir);
	default:
		sf_error("'%s' modifier applied to host",
			    get_modifier_by_id(proto));
	}
	/* NOTREACHED */
}


static struct block *
gen_host6(struct in6_addr *addr, struct in6_addr *mask, int proto, int dir)
{
	switch (proto) {

	case Q_DEFAULT:
	case Q_IPV6:
		return gen_hostop6(addr, mask, dir);

	default:
		sf_error("'%s' modifier applied to host6",
			    get_modifier_by_id(proto));
	}
}

struct block *
gen_proto_abbrev(int proto)
{
	struct block *b0 = NULL, *b1;

	switch (proto) {

	case Q_TCP:
		b1 = gen_proto(IPPROTO_TCP);
		break;

	case Q_UDP:
		b1 = gen_proto(IPPROTO_UDP);
		break;

	case Q_ICMP:
		b1 = gen_proto(IPPROTO_ICMP);
		b0 = gen_proto(IPPROTO_ICMPV6);
		gen_or(b0, b1);
		break;

	case Q_IP:
		b1 =  gen_linktype(ETHERTYPE_IP);
		break;

	case Q_IPV6:
		b1 = gen_linktype(ETHERTYPE_IPV6);
		break;

	case Q_AH:
		b1 = gen_proto(IPPROTO_AH);
		break;

	case Q_ESP:
		b1 = gen_proto(IPPROTO_ESP);
		break;

	case Q_PFSYNC:
		b1 = gen_proto(IPPROTO_PFSYNC);
		break;

	case Q_CARP:
		b1 = gen_proto(IPPROTO_CARP);
		break;

	default:
		sf_error("Unknown protocol abbreviation");
	}

	return b1;
}

#ifdef HAVE_PFSYNC_KEY
struct block *
gen_portop(int port, int proto, int dir)
{
	struct block *b0, *b1, *b2, *bi, *bo;
	const static int isrc_off = offsetof(pf_state_t, key[PF_SK_STACK].port[0]);
	const static int osrc_off = offsetof(pf_state_t, key[PF_SK_WIRE].port[1]);
	const static int idst_off = offsetof(pf_state_t, key[PF_SK_STACK].port[1]);
	const static int odst_off = offsetof(pf_state_t, key[PF_SK_WIRE].port[0]);

	const static int igwy1_off = offsetof(pf_state_t, key[PF_SK_WIRE].port[0]);
	const static int ogwy1_off = offsetof(pf_state_t, key[PF_SK_STACK].port[1]);
	const static int igwy2_off = offsetof(pf_state_t, key[PF_SK_WIRE].port[1]);
	const static int ogwy2_off = offsetof(pf_state_t, key[PF_SK_STACK].port[0]);

	port = ntohs(port);

	bi = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
	bo = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);

	switch (dir) {

	case Q_SRC:
		b1 = gen_cmp(osrc_off, BPF_H, (bpf_int32)port);
		gen_and(bo, b1);
		b0 = gen_cmp(isrc_off, BPF_H, (bpf_int32)port);
		gen_and(bi, b0);
		gen_or(b0, b1);
		break;

	case Q_DST:
		b1 = gen_cmp(odst_off, BPF_H, (bpf_int32)port);
		gen_and(bo, b1);
		b0 = gen_cmp(idst_off, BPF_H, (bpf_int32)port);
		gen_and(bi, b0);
		gen_or(b0, b1);
		break;

	case Q_GATEWAY:
		/* (in && (addr == igwy1 || addr == igwy2)) ||
		   (out && (addr == ogwy1 || addr == ogwy2))  phew! */
		b1 = gen_cmp(igwy1_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(igwy2_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		gen_and(bi, b1);
		b2 = gen_cmp(ogwy1_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(ogwy2_off, BPF_H, (bpf_int32)port);
		gen_or(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_AND:
		b1 = gen_cmp(isrc_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(idst_off, BPF_H, (bpf_int32)port);
		gen_and(b0, b1);
		gen_and(bi, b1);
		b2 = gen_cmp(osrc_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(odst_off, BPF_H, (bpf_int32)port);
		gen_and(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_OR:
		b1 = gen_cmp(isrc_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(idst_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		gen_and(bi, b1);
		b2 = gen_cmp(osrc_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(odst_off, BPF_H, (bpf_int32)port);
		gen_or(b2, b0);
		gen_and(bo, b0);
		gen_or(b0, b1);
		break;

	case Q_DEFAULT:
		b1 = gen_cmp(isrc_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(idst_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		b0 = gen_cmp(osrc_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		b0 = gen_cmp(odst_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid direcion specifier: %d", dir);
	}



	b0 = gen_proto(proto);
	gen_and(b0, b1);

	return b1;
}
#else
struct block *
gen_portop(int port, int proto, int dir)
{
	struct block *b0, *b1, *b2;
	const static int lan_off = offsetof(pf_state_t, lan.port);
	const static int gwy_off = offsetof(pf_state_t, gwy.port);
	const static int ext_off = offsetof(pf_state_t, ext.port);

	port = ntohs(port);

	switch (dir) {

	case Q_SRC:
		/* XXX can be simplified */
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);
		b1 = gen_cmp(lan_off, BPF_H, (bpf_int32)port);
		gen_and(b0, b1);
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
		b2 = gen_cmp(ext_off, BPF_H, (bpf_int32)port);
		gen_and(b0, b2);
		gen_or(b2, b1);
		break;

	case Q_DST:
		/* XXX can be simplified */
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_OUT);
		b1 = gen_cmp(ext_off, BPF_H, (bpf_int32)port);
		gen_and(b0, b1);
		b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B, (bpf_int32)PF_IN);
		b2 = gen_cmp(lan_off, BPF_H, (bpf_int32)port);
		gen_and(b0, b2);
		gen_or(b2, b1);
		break;

	case Q_GATEWAY:
		b1 = gen_cmp(gwy_off, BPF_W, (bpf_int32)port);
		break;

	case Q_AND:
		b1 = gen_cmp(ext_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(lan_off, BPF_H, (bpf_int32)port);
		gen_and(b0, b1);
		break;

	case Q_OR:
		b1 = gen_cmp(ext_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(lan_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		break;

	case Q_DEFAULT:
		b1 = gen_cmp(ext_off, BPF_H, (bpf_int32)port);
		b0 = gen_cmp(lan_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		b0 = gen_cmp(gwy_off, BPF_H, (bpf_int32)port);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid port direcion specifier: %d", dir);
	}

	b0 = gen_proto(proto);
	gen_and(b0, b1);

	return b1;
}
#endif

static struct block *
gen_port(int port, int ip_proto, int dir)
{
	struct block *b0, *b1;

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		b1 = gen_portop(port, ip_proto, dir);
		break;

	case PROTO_UNDEF:
		b0 = gen_portop(port, IPPROTO_TCP, dir);
		b1 = gen_portop(port, IPPROTO_UDP, dir);
		gen_or(b0, b1);
		break;

	default:
		sf_error("Internal error: Invalid IP protocol specifier: %d", dir);
	}

	return b1;
}

static int
lookup_proto(const char *name, int proto)
{
	int v;

	switch (proto) {

	case Q_DEFAULT:
	case Q_IP:
		v = pcap_nametoproto(name);
		if (v == PROTO_UNDEF)
			sf_error("unknown ip proto '%s'", name);
		break;
	default:
		v = PROTO_UNDEF;
		break;
	}
	return v;
}

struct block *
gen_scode(const char *name, struct qual q)
{
	int proto = q.proto;
	int dir = q.dir;
	int tproto;

	bpf_u_int32 mask, addr;
	int tproto6;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct addrinfo *res, *res0;
	struct in6_addr mask128;

	struct block *b, *tmp;
	int port, real_proto;

	switch (q.addr) {

	case Q_NET:
		addr = pcap_nametonetaddr(name);
		if (addr == 0)
			sf_error("unknown network '%s'", name);
		/* Left justify network addr and calculate its network mask */
		mask = 0xffffffff;
		while (addr && (addr & 0xff000000) == 0) {
			addr <<= 8;
			mask <<= 8;
		}
		return gen_host(addr, mask, proto, dir);

	case Q_DEFAULT:
	case Q_HOST:
		memset(&mask128, 0xff, sizeof(mask128));
		res0 = res = pcap_nametoaddrinfo(name);
		if (res == NULL)
			sf_error("unknown host '%s'", name);
		b = tmp = NULL;
		tproto = tproto6 = proto;
		if (tproto == Q_DEFAULT) {
			tproto = Q_IP;
			tproto6 = Q_IPV6;
		}
		for (res = res0; res; res = res->ai_next) {
			switch (res->ai_family) {
			case AF_INET:
				if (tproto == Q_IPV6)
					continue;
				
				sin = (struct sockaddr_in *)
					res->ai_addr;
				tmp = gen_host(ntohl(sin->sin_addr.s_addr),
					       0xffffffff, tproto, dir);
				break;
			case AF_INET6:
				if (tproto6 == Q_IP)
					continue;
				
				sin6 = (struct sockaddr_in6 *)
					res->ai_addr;
				tmp = gen_host6(&sin6->sin6_addr,
						&mask128, tproto6, dir);
				break;
			}
			if (b)
				gen_or(b, tmp);
			b = tmp;
		}
		freeaddrinfo(res0);
		if (b == NULL) {
			sf_error("unknown host '%s'%s", name,
				 (proto == Q_DEFAULT)
				 ? ""
				 : " for specified address family");
		}
		return b;

	case Q_PORT:
		if (proto != Q_DEFAULT && proto != Q_UDP && proto != Q_TCP)
			sf_error("illegal qualifier of 'port'");
		if (pcap_nametoport(name, &port, &real_proto) == 0)
			sf_error("unknown port '%s'", name);
		if (proto == Q_UDP) {
			if (real_proto == IPPROTO_TCP)
				sf_error("port '%s' is tcp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_UDP;
		}
		if (proto == Q_TCP) {
			if (real_proto == IPPROTO_UDP)
				sf_error("port '%s' is udp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_TCP;
		}

		b = gen_port(port, real_proto, dir);
		return b;

	case Q_PROTO:
		real_proto = lookup_proto(name, proto);
		if (real_proto >= 0)
			return gen_proto(real_proto);
		else
			sf_error("unknown protocol: %s", name);

	case Q_UNDEF:
		syntax();
		/* NOTREACHED */
	}
	abort();
	/* NOTREACHED */
}

struct block *
gen_mcode(const char *s1, const char *s2, int masklen, struct qual q)
{
	int nlen, mlen;
	bpf_u_int32 n, m;

	nlen = __pcap_atoin(s1, &n);
	/* Promote short ipaddr */
	n <<= 32 - nlen;

	if (s2 != NULL) {
		mlen = __pcap_atoin(s2, &m);
		/* Promote short ipaddr */
		m <<= 32 - mlen;
		if ((n & ~m) != 0)
			sf_error("non-network bits set in \"%s mask %s\"",
			    s1, s2);
	} else {
		/* Convert mask len to mask */
		if (masklen > 32)
			sf_error("mask length must be <= 32");
		m = 0xffffffff << (32 - masklen);
		if ((n & ~m) != 0)
			sf_error("non-network bits set in \"%s/%d\"",
			    s1, masklen);
	}

	switch (q.addr) {

	case Q_NET:
		return gen_host(n, m, q.proto, q.dir);

	default:
		sf_error("Mask syntax for networks only");
		/* NOTREACHED */
	}
}

struct block *
gen_ncode(const char *s, bpf_u_int32 v, struct qual q)
{
	bpf_u_int32 mask;
	int proto = q.proto;
	int dir = q.dir;
	int vlen;

	if (s == NULL)
		vlen = 32;
	else
		vlen = __pcap_atoin(s, &v);

	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
	case Q_NET:
		mask = 0xffffffff;
		if (s == NULL && q.addr == Q_NET) {
			/* Promote short net number */
			while (v && (v & 0xff000000) == 0) {
				v <<= 8;
				mask <<= 8;
			}
		} else {
			/* Promote short ipaddr */
			v <<= 32 - vlen;
			mask <<= 32 - vlen;
		}
		return gen_host(v, mask, proto, dir);

	case Q_PORT:
		if (proto == Q_UDP)
			proto = IPPROTO_UDP;
		else if (proto == Q_TCP)
			proto = IPPROTO_TCP;
		else if (proto == Q_DEFAULT)
			proto = PROTO_UNDEF;
		else
			sf_error("illegal qualifier of 'port'");
		
		return gen_port((int)v, proto, dir);

	case Q_PROTO:
		return gen_proto((int)v);

	case Q_UNDEF:
		syntax();
		/* NOTREACHED */

	default:
		abort();
		/* NOTREACHED */
	}
	/* NOTREACHED */
}

struct block *
gen_mcode6(const char *s1, const char *s2, int masklen, struct qual q)
{
	struct addrinfo *res;
	struct in6_addr *addr;
	struct in6_addr mask;
	struct block *b;
	u_int32_t *a, *m;

	if (s2)
		sf_error("no mask %s supported", s2);

	res = pcap_nametoaddrinfo(s1);
	if (!res)
		sf_error("invalid ip6 address %s", s1);
	if (res->ai_next)
		sf_error("%s resolved to multiple address", s1);
	addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

	if (sizeof(mask) * 8 < masklen)
		sf_error("mask length must be <= %u", (unsigned int)(sizeof(mask) * 8));
	memset(&mask, 0xff, masklen / 8);
	if (masklen % 8) {
		mask.s6_addr[masklen / 8] =
			(0xff << (8 - masklen % 8)) & 0xff;
	}

	a = (u_int32_t *)addr;
	m = (u_int32_t *)&mask;
	if ((a[0] & ~m[0]) || (a[1] & ~m[1])
	 || (a[2] & ~m[2]) || (a[3] & ~m[3])) {
		sf_error("non-network bits set in \"%s/%d\"", s1, masklen);
	}

	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
		if (masklen != 128)
			sf_error("Mask syntax for networks only");
		/* FALLTHROUGH */

	case Q_NET:
		b = gen_host6(addr, &mask, q.proto, q.dir);
		freeaddrinfo(res);
		return b;

	default:
		sf_error("invalid qualifier against IPv6 address");
		/* NOTREACHED */
	}
}

void
sappend(struct slist *s0, struct slist *s1)
{
	/*
	 * This is definitely not the best way to do this, but the
	 * lists will rarely get long.
	 */
	while (s0->next)
		s0 = s0->next;
	s0->next = s1;
}

static struct slist *
xfer_to_x(struct arth *a)
{
	struct slist *s;

	s = new_stmt(BPF_LDX|BPF_MEM);
	s->s.k = a->regno;
	return s;
}

static struct slist *
xfer_to_a(struct arth *a)
{
	struct slist *s;

	s = new_stmt(BPF_LD|BPF_MEM);
	s->s.k = a->regno;
	return s;
}

struct block *
gen_relation(int code, struct arth *a0, struct arth *a1, int reversed)
{
	struct slist *s0, *s1, *s2;
	struct block *b, *tmp;

	s0 = xfer_to_x(a1);
	s1 = xfer_to_a(a0);
	s2 = new_stmt(BPF_ALU|BPF_SUB|BPF_X);
	b = new_block(JMP(code));
	if (code == BPF_JGT || code == BPF_JGE) {
		reversed = !reversed;
		b->s.k = 0x80000000;
	}
	if (reversed)
		gen_not(b);

	sappend(s1, s2);
	sappend(s0, s1);
	sappend(a1->s, s0);
	sappend(a0->s, a1->s);

	b->stmts = a0->s;

	free_reg(a0->regno);
	free_reg(a1->regno);

	/* 'and' together protocol checks */
	if (a0->b) {
		if (a1->b) {
			gen_and(a0->b, tmp = a1->b);
		}
		else
			tmp = a0->b;
	} else
		tmp = a1->b;

	if (tmp)
		gen_and(tmp, b);

	return b;
}

struct arth *
gen_loadlen(void)
{
	int regno = alloc_reg();
	struct arth *a = (struct arth *)newchunk(sizeof(*a));
	struct slist *s;

	s = new_stmt(BPF_LD|BPF_LEN);
	s->next = new_stmt(BPF_ST);
	s->next->s.k = regno;
	a->s = s;
	a->regno = regno;

	return a;
}

struct arth *
gen_loadi(int val)
{
	struct arth *a;
	struct slist *s;
	int reg;

	a = (struct arth *)newchunk(sizeof(*a));

	reg = alloc_reg();

	s = new_stmt(BPF_LD|BPF_IMM);
	s->s.k = val;
	s->next = new_stmt(BPF_ST);
	s->next->s.k = reg;
	a->s = s;
	a->regno = reg;

	return a;
}

struct arth *
gen_neg(struct arth *a)
{
	struct slist *s;

	s = xfer_to_a(a);
	sappend(a->s, s);
	s = new_stmt(BPF_ALU|BPF_NEG);
	s->s.k = 0;
	sappend(a->s, s);
	s = new_stmt(BPF_ST);
	s->s.k = a->regno;
	sappend(a->s, s);

	return a;
}

struct arth *
gen_arth(int code, struct arth *a0, struct arth *a1)
{
	struct slist *s0, *s1, *s2;

	s0 = xfer_to_x(a1);
	s1 = xfer_to_a(a0);
	s2 = new_stmt(BPF_ALU|BPF_X|code);

	sappend(s1, s2);
	sappend(s0, s1);
	sappend(a1->s, s0);
	sappend(a0->s, a1->s);

	free_reg(a1->regno);

	s0 = new_stmt(BPF_ST);
	a0->regno = s0->s.k = alloc_reg();
	sappend(a0->s, s0);

	return a0;
}

static struct arth *
gen_load64(int hoff, int loff)
{
	struct arth *a;
	struct slist *s, *s1;
	int reg;

	a = (struct arth *)newchunk(sizeof(*a));
	reg = alloc_reg();

	if (hoff < 0) {
		/* XXX we only handle 32 bits */
		s = new_stmt(BPF_LD|BPF_ABS|BPF_W);
		s->s.k = loff;
	} else {
		s = new_stmt(BPF_LD|BPF_ABS|BPF_W);
		s->s.k = hoff;
		s1 = new_stmt(BPF_ALU|BPF_LSH|BPF_K);
		s1->s.k = 32;
		sappend(s, s1);
		s1 = new_stmt(BPF_MISC|BPF_TAX);
		s1->s.k = 0;
		sappend(s, s1);
		s1 = new_stmt(BPF_LD|BPF_ABS|BPF_W);
		s1->s.k = loff;
		sappend(s, s1);
		s1 = new_stmt(BPF_ALU|BPF_ADD|BPF_X);
		s1->s.k = 0;
		sappend(s, s1);
	}

	s1 = new_stmt(BPF_ST);
	s1->s.k = reg;
	sappend(s, s1);

	a->s = s;
	a->regno = reg;
	return a;
}

struct arth *
gen_loadbytes(int out)
{
	int loff, hoff;

#ifndef HAVE_INOUT_COUNT
	loff = offsetof(pf_state_t, bytes);
	hoff = -1;
#else
#ifdef HAVE_PFSYNC_STATE
	hoff = offsetof(pf_state_t, bytes[out ? 0:1]);
	loff = -1;
#else
#ifdef HAVE_STATE_COUNT_64
#if _BYTE_ORDER == _LITTLE_ENDIAN
	loff = offsetof(pf_state_t, bytes[out ? 0:1]);
	hoff = loff + sizeof(u_int32_t);
#else
	hoff = offsetof(pf_state_t, bytes[out ? 0:1]);
	loff = hoff + sizeof(u_int32_t);
#endif	/* _BYTE_ORDER */
#else
	loff = offsetof(pf_state_t, bytes[out ? 0:1]);
	hoff = -1;
#endif	/* HAVE_STATE_COUNT_64 */
#endif	/* HAVE_PFSYNC_STATE */
#endif	/* HAVE_INOUT_COUNT */

	return gen_load64(hoff, loff);
}


struct arth *
gen_loadpackets(int out)
{
	int loff, hoff;

#ifndef HAVE_INOUT_COUNT
	loff = offsetof(pf_state_t, packets);
	hoff = -1;
#else
#ifdef HAVE_PFSYNC_STATE
	hoff = offsetof(pf_state_t, packets[out ? 0:1]);
	loff = -1;
#else
#ifdef HAVE_STATE_COUNT_64
#if _BYTE_ORDER == _LITTLE_ENDIAN
	loff = offsetof(pf_state_t, packets[out ? 0:1]);
	hoff = loff + sizeof(u_int32_t);
#else
	hoff = offsetof(pf_state_t, packets[out ? 0:1]);
	loff = hoff + sizeof(u_int32_t);
#endif	/* _BYTE_ORDER */
#else
	loff = offsetof(pf_state_t, packets[out ? 0:1]);
	hoff = -1;
#endif	/* HAVE_STATE_COUNT_64 */
#endif	/* HAVE_PFSYNC_STATE */
#endif	/* HAVE_INOUT_COUNT */

	return gen_load64(hoff, loff);
}

struct arth *
gen_loadage(void)
{
	struct arth *a;
	struct slist *s;
	int reg;

	a = (struct arth *)newchunk(sizeof(*a));
	reg = alloc_reg();

	s = new_stmt(BPF_LD|BPF_ABS|BPF_W);
	s->s.k = offsetof(pf_state_t, creation);
	s->next = new_stmt(BPF_ST);
	s->next->s.k = reg;
	a->s = s;
	a->regno = reg;

	return a;
}

struct arth *
gen_loadexpire(void)
{
	struct arth *a;
	struct slist *s;
	int reg;

	a = (struct arth *)newchunk(sizeof(*a));
	reg = alloc_reg();

	s = new_stmt(BPF_LD|BPF_ABS|BPF_W);
	s->s.k = offsetof(pf_state_t, expire);
	s->next = new_stmt(BPF_ST);
	s->next->s.k = reg;
	a->s = s;
	a->regno = reg;

	return a;
}

/*
struct arth *
gen_loadage(void)
{
	int loff, hoff;

	loff = offsetof(pf_state_t, creation);
	hoff = -1;

	return gen_load64(hoff, loff);
}

struct arth *
gen_loadexpire(void)
{
	int loff, hoff;

	loff = offsetof(pf_state_t, expire);
	hoff = -1;

	return gen_load64(hoff, loff);
}
*/

/*
 * Here we handle simple allocation of the scratch registers.
 * If too many registers are alloc'd, the allocator punts.
 */
static int regused[BPF_MEMWORDS];
static int curreg;

/*
 * Return the next free register.
 */
static int
alloc_reg(void)
{
	int n = BPF_MEMWORDS;

	while (--n >= 0) {
		if (regused[curreg])
			curreg = (curreg + 1) % BPF_MEMWORDS;
		else {
			regused[curreg] = 1;
			return curreg;
		}
	}
	sf_error("too many registers needed to evaluate expression");
	/* NOTREACHED */
}

/*
 * Return a register to the table so it can
 * be used later.
 */
static void
free_reg(int n)
{
	regused[n] = 0;
}

static struct block *
gen_len(int jmp, int n)
{
	struct slist *s;
	struct block *b;

	s = new_stmt(BPF_LD|BPF_LEN);
	b = new_block(JMP(jmp));
	b->stmts = s;
	b->s.k = n;

	return b;
}

struct block *
gen_greater(int n)
{
	return gen_len(BPF_JGE, n);
}

struct block *
gen_less(int n)
{
	struct block *b;

	b = gen_len(BPF_JGT, n);
	gen_not(b);

	return b;
}

struct block *
gen_byteop(int op, int idx, int val)
{
	struct block *b;
	struct slist *s;

	switch (op) {
	default:
		abort();

	case '=':
		return gen_cmp((u_int)idx, BPF_B, (bpf_int32)val);

	case '<':
		b = gen_cmp((u_int)idx, BPF_B, (bpf_int32)val);
		b->s.code = JMP(BPF_JGE);
		gen_not(b);
		return b;

	case '>':
		b = gen_cmp((u_int)idx, BPF_B, (bpf_int32)val);
		b->s.code = JMP(BPF_JGT);
		return b;

	case '|':
		s = new_stmt(BPF_ALU|BPF_OR|BPF_K);
		break;

	case '&':
		s = new_stmt(BPF_ALU|BPF_AND|BPF_K);
		break;
	}
	s->s.k = val;
	b = new_block(JMP(BPF_JEQ));
	b->stmts = s;
	gen_not(b);

	return b;
}

/*
 * generate command for inbound/outbound.  It's here so we can
 * make it link-type specific.  'dir' = 0 implies "inbound",
 * = 1 implies "outbound".
 */
struct block *
gen_inbound(int dir)
{
	struct block *b0;

	b0 = gen_cmp(offsetof(pf_state_t, direction), BPF_B,
		     (bpf_int32)((dir == 0) ? PF_IN : PF_OUT));
	return (b0);
}


/* PF firewall log matched interface */
struct block *
gen_ifname(char *ifname)
{
#ifdef HAVE_STATE_IFNAME
	struct block *b0;
	u_int len, off;

	len = sizeof(((pf_state_t *)0)->pfs_ifname);
	off = offsetof(pf_state_t, pfs_ifname);

	if (strlen(ifname) >= len) {
		sf_error("ifname interface names can only be %d characters",
		    len - 1);
		/* NOTREACHED */
	}

	b0 = gen_bcmp(off, strlen(ifname), (unsigned char*) ifname);
	return (b0);
#else
	sf_error("ifname not supported in this OpenBSD release");
		/* NOTREACHED */
#endif
}

/* PF firewall log rule number */
struct block *
gen_rnr(int rnr)
{
	struct block *b0;

	b0 = gen_cmp(offsetof(pf_state_t, rule), BPF_W, (bpf_int32)rnr);

	return (b0);
}

