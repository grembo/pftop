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

/* #define HAVE_ALTQ */

typedef struct pfctl_state pf_state_t;
typedef struct pfsync_state_host pf_state_host_t;
typedef struct pfctl_state_peer pf_state_peer_t;

#endif
