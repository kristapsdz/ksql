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
 * Write the full message required for a ksql_stmt_xxx function when in
 * the parent of a parent-child daemon scenario.
 * Returns zero on failure, non-zero on success.
 * (We don't need to return the codes because the SQLite functions don't
 * as well.)
 */
static int
ksql_writecol(struct ksqlstmt *stmt, enum ksqlop op, 
	size_t col, void *buf, size_t bufsz)
{

	assert(KSQLSRV_ISPARENT(stmt->sql));

	if (KSQL_OK != ksql_writeop(stmt->sql, op))
		return(0);
	if (KSQL_OK != ksql_writeptr(stmt->sql, stmt->ptr))
		return(0);
	if (KSQL_OK != ksql_writesz(stmt->sql, col))
		return(0);
	if (KSQL_OK != ksql_readbuf(stmt->sql, buf, bufsz, 0))
		return(0);

	return(1);
}


/*
 * TODO: use a string buffer for "sql".
 */
enum ksqlc
ksqlsrv_stmt_alloc(struct ksql *p)
{
	struct ksqlstmt	*ss;
	char		*sql = NULL;
	size_t		 id;
	enum ksqlc	 c, cc;

	if (KSQL_OK != (c = ksql_readstr(p, &sql)))
		return(c);
	assert(NULL != sql);

	if (KSQL_OK != (c = ksql_readsz(p, &id))) {
		free(sql);
		return(c);
	}

	/* 
	 * Run operation first, ignoring "ss".
	 * Once this completes, a valid "ss" is attached to the
	 * database, so we don't need to manage the pointer.
	 */

	cc = ksql_stmt_alloc(p, &ss, sql, id);
	free(sql);

	if (KSQL_OK != (c = ksql_writecode(p, cc)))
		return(c);
	if (KSQL_OK != cc)
		return(cc);

	/* We now know that "ss" is non-NULL. */

	assert(NULL != ss);
	return(ksql_writeptr(p, ss));
}

const void *
ksql_stmt_blob(struct ksqlstmt *stmt, size_t col)
{
	size_t		 sz;
	char		*cp;
	struct kcache	*c;

	if ( ! KSQLSRV_ISPARENT(stmt->sql))
		return(sqlite3_column_blob(stmt->stmt, col));

	if (KSQL_OK != ksql_writeop(stmt->sql, KSQLOP_COL_BLOB))
		return(NULL);
	if (KSQL_OK != ksql_writeptr(stmt->sql, stmt->ptr))
		return(NULL);
	if (KSQL_OK != ksql_writesz(stmt->sql, col))
		return(NULL);

	/* 
	 * Note: ksql_stmt_blob doesn't return the byte size.
	 * We do so in ksqlsrv_stmt_blob instead.
	 * If the byte size is zero, then SQLite had a memory failure or
	 * is returning nothing in that space.
	 */

	if (KSQL_OK != ksql_readsz(stmt->sql, &sz))
		return(NULL);
	if (0 == sz)
		return(NULL);

	if (NULL == (cp = malloc(sz))) {
		ksql_err(stmt->sql, KSQL_MEM, strerror(ENOMEM));
		return(NULL);
	}

	if (KSQL_OK != ksql_readbuf(stmt->sql, cp, sz, 0)) {
		free(cp);
		return(NULL);
	}

	/* Put into our pointer cache. */

	if (NULL == (c = calloc(1, sizeof(struct kcache)))) {
		ksql_err(stmt->sql, KSQL_MEM, strerror(ENOMEM));
		free(cp);
		return(NULL);
	}
	TAILQ_INSERT_TAIL(&stmt->cache, c, entries);
	c->s = cp;
	return(c->s);
}

size_t
ksql_stmt_bytes(struct ksqlstmt *stmt, size_t col)
{
	size_t	 val;

	if ( ! KSQLSRV_ISPARENT(stmt->sql))
		return(sqlite3_column_bytes(stmt->stmt, col));
	return(ksql_writecol(stmt, KSQLOP_COL_BYTES, 
		col, &val, sizeof(size_t)) ? val : 0);
}

double
ksql_stmt_double(struct ksqlstmt *stmt, size_t col)
{
	double		 val;

	if ( ! KSQLSRV_ISPARENT(stmt->sql))
		return(sqlite3_column_double(stmt->stmt, col));
	return(ksql_writecol(stmt, KSQLOP_COL_DOUBLE, 
		col, &val, sizeof(double)) ? val : 0.0);
}

int
ksql_stmt_isnull(struct ksqlstmt *stmt, size_t col)
{
	int	 val;

	if ( ! KSQLSRV_ISPARENT(stmt->sql))
		return(SQLITE_NULL == 
		       sqlite3_column_type(stmt->stmt, col));
	return(ksql_writecol(stmt, KSQLOP_COL_ISNULL, 
		col, &val, sizeof(int)) ? val : 0);
}

int64_t
ksql_stmt_int(struct ksqlstmt *stmt, size_t col)
{
	int64_t		 val;

	if ( ! KSQLSRV_ISPARENT(stmt->sql))
		return(sqlite3_column_int64(stmt->stmt, col));
	return(ksql_writecol(stmt, KSQLOP_COL_INT, 
		col, &val, sizeof(int64_t)) ? val : 0);
}

const char *
ksql_stmt_str(struct ksqlstmt *stmt, size_t col)
{
	char		*cp;
	size_t		 sz;
	struct kcache	*c;

	if ( ! KSQLSRV_ISPARENT(stmt->sql))
		return((char *)sqlite3_column_text(stmt->stmt, col));

	/* 
	 * This is a little tricky because we need to handle
	 * out-of-memory conditions for ourselves, our child, and SQLite
	 * itself.
	 */

	if (KSQL_OK != ksql_writeop(stmt->sql, KSQLOP_COL_STR))
		return(NULL);
	if (KSQL_OK != ksql_writeptr(stmt->sql, stmt->ptr))
		return(NULL);
	if (KSQL_OK != ksql_writesz(stmt->sql, col))
		return(NULL);

	/*
	 * If we get a zero-sized buffer, that means that SQLite
	 * couldn't allocate for the string and returned NULL.
	 */

	if (KSQL_OK != ksql_readsz(stmt->sql, &sz))
		return(NULL);
	if (0 == sz)
		return(NULL);

	/* Allocate and nil-terminate, then fill. */

	if (NULL == (cp = malloc(sz))) {
		ksql_err(stmt->sql, KSQL_MEM, strerror(ENOMEM));
		return(NULL);
	}
	cp[sz - 1] = '\0';

	/* 
	 * If we have a one-length string, it's empty so don't pass into
	 * the readbuf function (it will assert).
	 */

	if (sz > 1 &&
	    KSQL_OK != ksql_readbuf(stmt->sql, cp, sz - 1, 0)) {
		free(cp);
		return(NULL);
	}

	/* Put into our pointer cache. */

	if (NULL == (c = calloc(1, sizeof(struct kcache)))) {
		ksql_err(stmt->sql, KSQL_MEM, strerror(ENOMEM));
		free(cp);
		return(NULL);
	}
	TAILQ_INSERT_TAIL(&stmt->cache, c, entries);
	c->s = cp;
	return(c->s);
}
