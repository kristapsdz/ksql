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
#include <stdlib.h>
#include <string.h>

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

enum ksqlc
ksqlsrv_stmt_bytes(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	size_t		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);
	val = ksql_stmt_bytes(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(size_t)));
}

enum ksqlc
ksqlsrv_stmt_double(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	double		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);
	val = ksql_stmt_double(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(double)));
}

enum ksqlc
ksqlsrv_stmt_isnull(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	int		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);
	val = ksql_stmt_isnull(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(int)));
}

enum ksqlc
ksqlsrv_stmt_int(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	int64_t		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);
	val = ksql_stmt_int(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(int64_t)));
}

enum ksqlc
ksqlsrv_stmt_blob(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col, sz;
	const char	*val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);

	/* Get both the size and pointer first. */

	sz = ksql_stmt_bytes(stmt, col);
	val = ksql_stmt_str(stmt, col);

	/* 
	 * If val is NULL, SQLite couldn't allocate OR the size of the
	 * buffer was zero.
	 * We want to handle both conditions, so construe the number of
	 * bytes as zero either way and don't transmit.
	 */

	if (NULL == val)
		sz = 0;
	if (KSQL_OK != (c = ksql_writesz(p, sz)))
		return(c);
	if (0 != sz)
		c = ksql_writebuf(p, val, sz);
	return(c);
}

enum ksqlc
ksqlsrv_stmt_str(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col, sz;
	const char	*val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);

	/*
	 * SQLite returns NULL on allocation failure.
	 * So we do something special here.
	 * Send the string *buffer* length, which is always non-zero to
	 * account for the nil terminator.
	 * If that's zero, then we know that we have a NULL.
	 * If that's one, then it's a zero-length string.
	 */

	val = ksql_stmt_str(stmt, col);
	sz = NULL == val ? 0 : strlen(val) + 1;

	if (KSQL_OK != (c = ksql_writesz(p, sz)))
		return(c);
	if (sz > 1)
		c = ksql_writebuf(p, val, sz - 1);
	return(c);
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
		ksql_err(stmt->sql, KSQL_MEM, NULL);
		return(NULL);
	}

	if (KSQL_OK != ksql_readbuf(stmt->sql, cp, sz, 0)) {
		free(cp);
		return(NULL);
	}

	/* Put into our pointer cache. */

	if (NULL == (c = calloc(1, sizeof(struct kcache)))) {
		ksql_err(stmt->sql, KSQL_MEM, NULL);
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
		ksql_err(stmt->sql, KSQL_MEM, NULL);
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
		ksql_err(stmt->sql, KSQL_MEM, NULL);
		free(cp);
		return(NULL);
	}
	TAILQ_INSERT_TAIL(&stmt->cache, c, entries);
	c->s = cp;
	return(c->s);
}
