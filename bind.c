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

enum ksqlc
ksqlsrv_bind(struct ksql *p, enum ksqlop op)
{
	enum ksqlc	 c;
	size_t		 pos;
	char		*buf = NULL;
	struct ksqlstmt	*ss;
	size_t		 bufsz;

	if (KSQL_OK != (c = ksql_readptr(p, &ss)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &pos)))
		return(c);

	if (KSQLOP_BIND_TEXT == op) {
		if (KSQL_OK != (c = ksql_readstr(p, &buf)))
			return(c);
		c = ksql_bind_str(ss, pos, buf);
	} else if (KSQLOP_BIND_ZBLOB == op) {
		if (KSQL_OK != (c = ksql_readsz(p, &bufsz)))
			return(c);
		c = ksql_bind_zblob(ss, pos, bufsz);
	} else if (KSQLOP_BIND_NULL != op) {
		if (KSQL_OK != (c = ksql_readsz(p, &bufsz)))
			return(c);
		/* FIXME: handle zero-length. */
		if (NULL == (buf = malloc(bufsz))) {
			buf = strerror(errno);
			return(ksql_err(p, KSQL_MEM, buf));
		}
		c = ksql_readbuf(p, buf, bufsz, 0);
		if (KSQL_OK != c) {
			free(buf);
			return(c);
		}
		switch (op) {
		case (KSQLOP_BIND_BLOB):
			c = ksql_bind_blob(ss, pos, buf, bufsz);
			break;
		case (KSQLOP_BIND_DOUBLE):
			assert(bufsz == sizeof(double));
			c = ksql_bind_double(ss, pos, *(double *)buf);
			break;
		case (KSQLOP_BIND_INT):
			assert(bufsz == sizeof(int64_t));
			c = ksql_bind_int(ss, pos, *(int64_t *)buf);
			break;
		default:
			abort();
		}
	} else
		c = ksql_bind_null(ss, pos);

	free(buf);
	return(ksql_writecode(p, c));
}

enum ksqlc
ksql_bind_zblob(struct ksqlstmt *stmt, size_t pos, size_t valsz)
{
	int	 rc;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_ZBLOB, pos, NULL, valsz));
	if (pos >= stmt->bcols)
		return(ksql_verr(stmt->sql, KSQL_BINDCOL, 
			"parameter index %zu exceeds maximum "
			"index %zu", pos, stmt->bcols - 1));
	rc = sqlite3_bind_zeroblob(stmt->stmt, pos + 1, valsz);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_blob(struct ksqlstmt *stmt, 
	size_t pos, const void *val, size_t valsz)
{
	int	rc;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_BLOB, pos, val, valsz));

	if (pos >= stmt->bcols)
		return(ksql_verr(stmt->sql, KSQL_BINDCOL, 
			"parameter index %zu exceeds maximum "
			"index %zu", pos, stmt->bcols - 1));
	rc = sqlite3_bind_blob
		(stmt->stmt, pos + 1, val, valsz, SQLITE_TRANSIENT);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_str(struct ksqlstmt *stmt, size_t pos, const char *val)
{
	int	 rc;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_TEXT, pos, val, 0));

	if (pos >= stmt->bcols)
		return(ksql_verr(stmt->sql, KSQL_BINDCOL, 
			"parameter index %zu exceeds maximum "
			"index %zu", pos, stmt->bcols - 1));
	rc = sqlite3_bind_text
		(stmt->stmt, pos + 1, val, -1, SQLITE_TRANSIENT);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_double(struct ksqlstmt *stmt, size_t pos, double val)
{
	int	 rc;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_DOUBLE, pos, 
			&val, sizeof(double)));
	if (pos >= stmt->bcols)
		return(ksql_verr(stmt->sql, KSQL_BINDCOL, 
			"parameter index %zu exceeds maximum "
			"index %zu", pos, stmt->bcols - 1));
	rc = sqlite3_bind_double(stmt->stmt, pos + 1, val);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_null(struct ksqlstmt *stmt, size_t pos)
{

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_NULL, pos, NULL, 0));
	if (pos >= stmt->bcols)
		return(ksql_verr(stmt->sql, KSQL_BINDCOL, 
			"parameter index %zu exceeds maximum "
			"index %zu", pos, stmt->bcols - 1));
	if (SQLITE_OK == sqlite3_bind_null(stmt->stmt, pos + 1))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_int(struct ksqlstmt *stmt, size_t pos, int64_t val)
{

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_INT, pos, 
			&val, sizeof(int64_t)));
	if (pos >= stmt->bcols)
		return(ksql_verr(stmt->sql, KSQL_BINDCOL, 
			"parameter index %zu exceeds maximum "
			"index %zu", pos, stmt->bcols - 1));
	if (SQLITE_OK == sqlite3_bind_int64(stmt->stmt, pos + 1, val))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

