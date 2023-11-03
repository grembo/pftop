%{
/*	$OpenBSD: grammar.y,v 1.16 2007/01/02 18:31:21 reyk Exp $	*/
/*	$Id: sf-grammer.y,v 1.3 2007/10/01 20:39:40 canacar Exp $	*/

/*
 * Copyright (c) 2007 Can Erkin Acar <canacar@gmail.com>
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
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
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <stdio.h>
#include <string.h>

#include <pcap/pcap.h>

#include "sf-gencode.h"
#include <pcap-namedb.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(char *msg)
{
	++n_errors;
	sf_error("%s", msg);
	/* NOTREACHED */
}

#ifndef YYBISON
int yyparse(void);

int
pcap_parse()
{
	return (yyparse());
}
#endif

%}

%union {
	int i;
	bpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		struct block *b;
	} blk;
	struct block *rblk;
}

%type	<blk>	expr id nid pid term rterm qid
%type	<blk>	head phead
%type	<i>	pqual dqual aqual
%type	<a>	arth narth
%type	<i>	pname pnum relop irelop
%type	<blk>	and or paren not null prog
%type	<rblk>	other stvar

%token  DST SRC HOST GATEWAY
%token  NET MASK PORT PROTO
%token  IP TCP UDP ICMP
%token  IPV6 AH ESP PFSYNC CARP
%token  NUM INBOUND OUTBOUND
%token  IFNAME RNR
%token	GEQ LEQ NEQ
%token	ID HID HID6
%token	LSH RSH
%token  IBYTES IPKTS OBYTES OPKTS AGE EXPIRE

%type	<s> ID HID HID6
%type	<s> RNR IFNAME
%type	<i> NUM

%left OR AND
%nonassoc  '!'
%left '|'
%left '&'
%left LSH RSH
%left '+' '-'
%left '*' '/'
%nonassoc UMINUS
%%
prog:	  null expr
{
	finish_parse($2.b);
}
	| null
	;
null:	  /* null */		{ $$.q = qerr; }
	;
expr:	  term
	| expr and term		{ gen_and($1.b, $3.b); $$ = $3; }
	| expr and id		{ gen_and($1.b, $3.b); $$ = $3; }
	| expr or term		{ gen_or($1.b, $3.b); $$ = $3; }
	| expr or id		{ gen_or($1.b, $3.b); $$ = $3; }
	;
and:	  AND			{ $$ = $<blk>0; }
	;
or:	  OR			{ $$ = $<blk>0; }
	;
id:	  nid
	| pnum			{ $$.b = gen_ncode(NULL, (bpf_u_int32)$1,
						   $$.q = $<blk>0.q); }
	| paren pid ')'		{ $$ = $2; }
	;
/* this is a host or port identifier */
nid:	  ID			{ $$.b = gen_scode($1, $$.q = $<blk>0.q); }
	| HID '/' NUM		{ $$.b = gen_mcode($1, NULL, $3,
				    $$.q = $<blk>0.q); }
	| HID MASK HID		{ $$.b = gen_mcode($1, $3, 0,
				    $$.q = $<blk>0.q); }
	| HID			{
				  $$.q = $<blk>0.q;
				  $$.b = gen_ncode($1, 0, $$.q);
				}
	| HID6 '/' NUM		{
				  $$.b = gen_mcode6($1, NULL, $3,
				    $$.q = $<blk>0.q);
				}
	| HID6			{
				  $$.b = gen_mcode6($1, 0, 128,
				    $$.q = $<blk>0.q);
				}
	| not id		{ gen_not($2.b); $$ = $2; }
	;
not:	  '!'			{ $$ = $<blk>0; }
	;
paren:	  '('			{ $$ = $<blk>0; }
	;
pid:	  nid
	| qid and id		{ gen_and($1.b, $3.b); $$ = $3; }
	| qid or id		{ gen_or($1.b, $3.b); $$ = $3; }
	;
qid:	  pnum			{ $$.b = gen_ncode(NULL, (bpf_u_int32)$1,
						   $$.q = $<blk>0.q); }
	| pid
	;
/* a term in an expression */
term:	  rterm
	| not term		{ gen_not($2.b); $$ = $2; }
	;
/* proto, direction, address qualifiers, followed by id */
head:	  pqual dqual aqual	{ QSET($$.q, $1, $2, $3); }
	| pqual dqual		{ QSET($$.q, $1, $2, Q_DEFAULT); }
	| pqual aqual		{ QSET($$.q, $1, Q_DEFAULT, $2); }
	;

phead:	  pqual PROTO	 	{ QSET($$.q, $1, Q_DEFAULT, Q_PROTO); }
	;
rterm:	  head id		{ $$ = $2; }
	| phead id		{ $$ = $2; }
	| phead pname		{ $$.b = gen_proto_abbrev($2); $$.q = qerr; }
	| paren expr ')'	{ $$.b = $2.b; $$.q = $1.q; }
	| pname			{ $$.b = gen_proto_abbrev($1); $$.q = qerr; }
	| arth relop arth	{ $$.b = gen_relation($2, $1, $3, 0);
				  $$.q = qerr; }
	| arth irelop arth	{ $$.b = gen_relation($2, $1, $3, 1);
				  $$.q = qerr; }
	| other			{ $$.b = $1; $$.q = qerr; }
	;
/* protocol level qualifiers */
pqual:	  pname
	|			{ $$ = Q_DEFAULT; }
	;
/* 'direction' qualifiers */
dqual:	  SRC			{ $$ = Q_SRC; }
	| DST			{ $$ = Q_DST; }
	| GATEWAY		{ $$ = Q_GATEWAY; }
	| SRC OR DST		{ $$ = Q_OR; }
	| DST OR SRC		{ $$ = Q_OR; }
	| SRC AND DST		{ $$ = Q_AND; }
	| DST AND SRC		{ $$ = Q_AND; }
	;
/* address type qualifiers */
aqual:	  HOST			{ $$ = Q_HOST; }
	| NET			{ $$ = Q_NET; }
	| PORT			{ $$ = Q_PORT; }
	;
/* predefined protocol names */
pname:	  IP			{ $$ = Q_IP; }
	| TCP			{ $$ = Q_TCP; }
	| UDP			{ $$ = Q_UDP; }
	| ICMP			{ $$ = Q_ICMP; }
	| IPV6			{ $$ = Q_IPV6; }
	| AH			{ $$ = Q_AH; }
	| ESP			{ $$ = Q_ESP; }
	| PFSYNC		{ $$ = Q_PFSYNC; }
	| CARP			{ $$ = Q_CARP; }
	;
/* Other operations */
other:	  INBOUND		{ $$ = gen_inbound(0); }
	| OUTBOUND		{ $$ = gen_inbound(1); }
	| stvar			{ $$ = $1; }
	;
/* state variables */
stvar:	  IFNAME ID		{ $$ = gen_ifname($2); }
	| RNR NUM		{ $$ = gen_rnr($2); }
	;
/* relational and negated relational ops */
relop:	  '>'			{ $$ = BPF_JGT; }
	| GEQ			{ $$ = BPF_JGE; }
	| '='			{ $$ = BPF_JEQ; }
	;
irelop:	  LEQ			{ $$ = BPF_JGT; }
	| '<'			{ $$ = BPF_JGE; }
	| NEQ			{ $$ = BPF_JEQ; }
	;
/* arithmetic operations  */
arth:	  pnum			{ $$ = gen_loadi($1); }
	| narth
	;
narth:	  arth '+' arth			{ $$ = gen_arth(BPF_ADD, $1, $3); }
	| arth '-' arth			{ $$ = gen_arth(BPF_SUB, $1, $3); }
	| arth '*' arth			{ $$ = gen_arth(BPF_MUL, $1, $3); }
	| arth '/' arth			{ $$ = gen_arth(BPF_DIV, $1, $3); }
	| arth '&' arth			{ $$ = gen_arth(BPF_AND, $1, $3); }
	| arth '|' arth			{ $$ = gen_arth(BPF_OR, $1, $3); }
	| arth LSH arth			{ $$ = gen_arth(BPF_LSH, $1, $3); }
	| arth RSH arth			{ $$ = gen_arth(BPF_RSH, $1, $3); }
	| '-' arth %prec UMINUS		{ $$ = gen_neg($2); }
	| paren narth ')'		{ $$ = $2; }
	| IBYTES			{ $$ = gen_loadbytes(0); }
	| OBYTES			{ $$ = gen_loadbytes(1); }
	| IPKTS				{ $$ = gen_loadpackets(0); }
	| OPKTS				{ $$ = gen_loadpackets(1); }
	| AGE				{ $$ = gen_loadage(); }
	| EXPIRE			{ $$ = gen_loadexpire(); }
	;
/* number with optional parantheses */
pnum:	  NUM
	| paren pnum ')'	{ $$ = $2; }
	;
%%
