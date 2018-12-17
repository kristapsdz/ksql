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

#if HAVE_SYS_QUEUE
# include <sys/queue.h>
#endif 

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <sqlite3.h>

#include "ksql.h"
#include "extern.h"

/*
 * Hard-coded string name for errors.
 * Those without a value aren't errors, just conditions.
 */
static	const char * const ksqlcs[] = {
	NULL, /* KSQL_OK */
	NULL, /* KSQL_DONE */
	NULL, /* KSQL_ROW */
	NULL, /* KSQL_CONSTRAINT */
	"memory exhausted", /* KSQL_MEM */
	"database not open", /* KSQL_NOTOPEN */
	"database already open", /* KSQL_ALREADYOPEN */
	"database error", /* KSQL_DB */
	"transaction already open or not yet open", /* KSQL_TRANS */
	"statement(s) open on exit", /* KSQL_STMT */
	"closing on exit", /* KSQL_EXIT */
	"system error", /* KSQL_SYSTEM */
	NULL, /* KSQL_EOF */
	"security violation", /* KSQL_SECURITY */
	"invalid bind column index", /* KSQL_BINDCOL */
	"invalid result column index", /* KSQL_RESULTCOL */
	"NULL value when requesting result", /* KSQL_NULL */
	"request for results without any rows", /* KSQL_NORESULTS */
};

/*
 * If there's an error function, use it to print "msg".
 * Don't do anything else (i.e., don't exit).
 * This can be used to simply print errors and messages.
 * Does nothing if there's no error handler.
 */
void
ksql_err_noexit(struct ksql *p, enum ksqlc erc, const char *msg)
{

	if (NULL == msg)
		msg = ksqlcs[erc];
	assert(NULL != msg);
	if (NULL != p->cfg.err)
		p->cfg.err(p->cfg.arg, erc, p->dbfile, msg);
}

/*
 * See ksql_dberr().
 */
enum ksqlc
ksql_err(struct ksql *p, enum ksqlc erc, const char *msg)
{

	ksql_err_noexit(p, erc, msg);
	if (KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);
	return(erc);
}

/*
 * This pass-through to ksql_err() accepts variable parameters.
 * They must resolve to less than 1024 characters before truncation.
 */
enum ksqlc
ksql_verr(struct ksql *p, enum ksqlc erc, const char *fmt, ...)
{
	va_list  ap;
	char	 buf[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return ksql_err(p, erc, buf);
}

/*
 * Pass a database error from SQLite to the error printing function.
 * If no database error has occurred, this will print something
 * harmless.
 * Does nothing if there's no database-error handler.
 */
void
ksql_dberr_noexit(struct ksql *p)
{

	if (NULL == p->cfg.dberr)
		return;
	p->cfg.dberr(p->cfg.arg, 
		sqlite3_errcode(p->db),
		sqlite3_extended_errcode(p->db),
		p->dbfile, sqlite3_errmsg(p->db));
}

/*
 * Pass an error to the error handler, if found.
 * Then if we're exiting on errors, do it here.
 */
enum ksqlc
ksql_dberr(struct ksql *p)
{

	ksql_dberr_noexit(p);
	if (KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);
	return(KSQL_DB);
}

void
ksqlitedbmsg(void *arg, int sql3, 
	int esql3, const char *file, const char *msg)
{

	(void)arg;
	if (NULL != file)
		warnx("%s: %s (error code %d, extended %d)", 
			file, msg, sql3, esql3);
	else
		warnx("%s (error code %d, extended %d)", 
			msg, sql3, esql3);
}

void
ksqlitemsg(void *arg, enum ksqlc code, 
	const char *file, const char *msg)
{

	(void)arg;
	if (NULL != file)
		warnx("%s: %s (error code %d)", file, msg, code);
	else
		warnx("%s (error code %d)", msg, code);
}

/*
 * Like ksqlitemsg() but accepting variable arguments.
 * Internally this will invoke vsnprintf(), which will truncate the
 * message to 1023 Bytes.
 * MAKE SURE YOUR MESSAGES ARE BOUND IN SIZE.
 */
void
ksqlitevmsg(const struct ksql *p, 
	enum ksqlc code, const char *fmt, ...)
{
	va_list	 ap;
	char	 msg[1024];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (NULL != p->dbfile)
		warnx("%s: %s (error code %d)", p->dbfile, msg, code);
	else
		warnx("%s (error code %d)", msg, code);
}

