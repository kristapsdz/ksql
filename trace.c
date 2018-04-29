/*	$Id$ */
/*
 * Copyright (c) 2016--2018 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#if ! HAVE_SOCK_NONBLOCK
# include <fcntl.h>
#endif
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "ksql.h"
#include "extern.h"

/*
 * Used by SQLite when tracing events.
 * Passes right through to ksql_err_noexit().
 */
static void
ksql_tracemsg(void *pArg, int iErrCode, const char *zMsg)
{
	struct ksql	*p = pArg;

	(void)iErrCode;

	ksql_err_noexit(p, KSQL_OK, zMsg);
}

enum ksqlc
ksql_trace(struct ksql *p)
{
	enum ksqlc	 c, cc;
	int		 rc;

	if (KSQLSRV_ISPARENT(p)) {
		ksql_writeop(p, KSQLOP_TRACE);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	} 

	rc = sqlite3_config
		(SQLITE_CONFIG_LOG, ksql_tracemsg, p);

	if (SQLITE_MISUSE == rc)
		cc = KSQL_ALREADYOPEN;
	else if (SQLITE_OK != rc)
		cc = KSQL_SYSTEM;
	else
		cc = KSQL_OK;

	return(ksql_writecode(p, cc));
}

enum ksqlc
ksql_untrace(struct ksql *p)
{
	enum ksqlc	 c, cc;
	int		 rc;

	if (KSQLSRV_ISPARENT(p)) {
		ksql_writeop(p, KSQLOP_UNTRACE);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	} 

	rc = sqlite3_config
		(SQLITE_CONFIG_LOG, NULL, NULL);

	if (SQLITE_MISUSE == rc)
		cc = KSQL_ALREADYOPEN;
	else if (SQLITE_OK != rc)
		cc = KSQL_SYSTEM;
	else
		cc = KSQL_OK;

	return(ksql_writecode(p, cc));
}
