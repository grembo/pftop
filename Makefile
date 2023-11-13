#	$Id: Makefile,v 1.17 2007/10/01 02:27:13 canacar Exp $

# set OS level if not already defined
OSLEVEL?=   ${OSrev}
LOCALBASE?= /usr/local

PROG=	pftop
SRCS=	pftop.c cache.c engine.c
SRCS+=	sf-gencode.c sf-grammer.y sf-scanner.l pcap-nametoaddr.c
SRCS+=  bpf_optimize.c bpf_filter.c bpf_dump.c bpf_image.c
MAN=	pftop.8

CFLAGS+= -Wall -Wno-unneeded-internal-declaration -DOS_LEVEL=${OSLEVEL}
LDADD+= -lcurses -lpfctl

MANDIR=${LOCALBASE}/man/man
BINDIR=${LOCALBASE}/sbin

.y.c:
	${YACC.y} -d -b ${.TARGET:R} -o ${.TARGET} ${.IMPSRC}

.include <bsd.prog.mk>
