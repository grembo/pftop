/* $Id: config.h,v 1.9 2007/10/03 05:52:36 canacar Exp $ */
/*
 * Copyright (c) 2001, 2007 Can Erkin Acar <canacar@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdbool.h>
#include <unistd.h>

#include <sys/counter.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>

#include <libpfctl.h>

#if OS_LEVEL > 30
#define HAVE_STATE_NOROUTE
#define HAVE_DEVICE_RO
#define HAVE_TREE_H
#define HAVE_QUEUE_H
#define HAVE_PF_ROUTE
#define HAVE_RULE_LABELS
#endif

#if OS_LEVEL > 31
#define HAVE_RULE_NUMBER
#define HAVE_ADDR_WRAP
#define HAVE_RULE_STATES
#define HAVE_RULE_IFNOT
#define HAVE_PROTO_NAMES
#define HAVE_MAX_STATES
#define HAVE_MAX_MSS
#define HAVE_RULE_UGID
#endif

#if OS_LEVEL > 32
#define HAVE_ADDR_MASK
#define HAVE_ADDR_TYPE
/* #define HAVE_ALTQ */
#define HAVE_RULE_TOS
#define HAVE_OP_RRG
#endif

#if OS_LEVEL > 33
#define HAVE_INOUT_COUNT
#define HAVE_TAGS
#define HAVE_RULE_NATPASS
#endif

#if OS_LEVEL > 34
#define HAVE_STATE_IFNAME
#endif

#if OS_LEVEL > 35
#define HAVE_NEG
#define HAVE_RULESETS
#endif

#if OS_LEVEL > 37
#define HAVE_INOUT_COUNT_RULES
#endif

#if OS_LEVEL > 38
#define HAVE_STATE_COUNT_64
#endif

#if OS_LEVEL > 41
#define HAVE_PFSYNC_STATE
#endif

#if OS_LEVEL > 43
#define HAVE_PFSYNC_KEY
#endif

#ifdef HAVE_PFSYNC_STATE
#if OS_LEVEL > 45
typedef struct pfctl_state pf_state_t;
#else
typedef struct pfctl_state pf_state_t;
#endif
typedef struct pfsync_state_host pf_state_host_t;
typedef struct pfctl_state_peer pf_state_peer_t;
#define COUNTER(c) (c)
#define pfs_ifname ifname
#else
typedef struct pf_state pf_state_t;
typedef struct pf_state_host pf_state_host_t;
typedef struct pf_state_peer pf_state_peer_t;
#define COUNTER(c) (c)
#define pfs_ifname u.ifname
#endif

#endif
