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

static int
ksql_result_isfatal(enum ksqlc c)
{

	return KSQL_OK != c;
}

/*
 * Make sure the result at column "col" is accessible to the current
 * statement.
 * Returns KSQL_OK if it is or an error otherwise.
 */
static enum ksqlc
ksql_result_check(struct ksqlstmt *stmt, size_t col)
{

	if ( ! stmt->hasrow)
		return ksql_verr(stmt->sql, KSQL_NORESULTS, 
			"result index %zu without any rows", col);
	if (col >= stmt->rcols) 
		return ksql_verr(stmt->sql, KSQL_RESULTCOL, 
			"result index %zu exceeds maximum "
			"index %zu", col, stmt->rcols - 1);
	if (SQLITE_NULL == sqlite3_column_type(stmt->stmt, col))
		return ksql_verr(stmt->sql, KSQL_NULL, 
			"result requested for null column %zu", col);

	return KSQL_OK;
}

/*
 * Write the full message required for a ksql_result_xxx function when in
 * the parent of a parent-child daemon scenario.
 * This checks the return code of the child *before* trying to read the
 * result, so we never pass a bogus result from the child to the parent.
 */
static enum ksqlc
ksql_readres(struct ksqlstmt *stmt, enum ksqlop op, 
	size_t col, void *buf, size_t bufsz)
{
	enum ksqlc	 c, code;

	assert(KSQLSRV_ISPARENT(stmt->sql));

	if (KSQL_OK != (c = ksql_writeop(stmt->sql, op)) ||
	    KSQL_OK != (c = ksql_writeptr(stmt->sql, stmt->ptr)) ||
	    KSQL_OK != (c = ksql_writesz(stmt->sql, col)) ||
	    KSQL_OK != (c = ksql_readcode(stmt->sql, &code)))
		return c;
	if (ksql_result_isfatal(code))
		return code;
	if (KSQL_OK != (c = ksql_readbuf(stmt->sql, buf, bufsz, 0)))
		return c;

	return code;
}

enum ksqlc
ksqlsrv_result_blob(struct ksql *p)
{
	enum ksqlc	 c, cc;
	struct ksqlstmt	*stmt;
	size_t		 col, sz = 0;
	const void	*val = NULL;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;

	if (KSQL_OK == (c = ksql_result_check(stmt, col))) {
		sz = sqlite3_column_bytes(stmt->stmt, col);
		val = sqlite3_column_blob(stmt->stmt, col);
	}

	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (ksql_result_isfatal(c))
		return c;

	/* Check code *before* writing result. */
	if (KSQL_OK != (c = ksql_writebuf(p, &sz, sizeof(size_t))))
		return c;
	return ksql_writebuf(p, val, sz);
}

enum ksqlc
ksqlsrv_result_isnull(struct ksql *p)
{
	enum ksqlc	 c, cc;
	struct ksqlstmt	*stmt;
	size_t		 col;
	int		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;
	c = ksql_result_isnull(stmt, &val, col);
	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (ksql_result_isfatal(c))
		return c;

	/* Check code *before* writing result. */
	return ksql_writebuf(p, &val, sizeof(int));
}

enum ksqlc
ksqlsrv_result_bytes(struct ksql *p)
{
	enum ksqlc	 c, cc;
	struct ksqlstmt	*stmt;
	size_t		 col, val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;
	c = ksql_result_bytes(stmt, &val, col);
	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (ksql_result_isfatal(c))
		return c;

	/* Check code *before* writing result. */
	return ksql_writebuf(p, &val, sizeof(size_t));
}

enum ksqlc
ksqlsrv_result_double(struct ksql *p)
{
	enum ksqlc	 c, cc;
	struct ksqlstmt	*stmt;
	size_t		 col;
	double		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;
	c = ksql_result_double(stmt, &val, col);
	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (ksql_result_isfatal(c))
		return c;

	/* Check code *before* writing result. */
	return ksql_writebuf(p, &val, sizeof(double));
}

enum ksqlc
ksqlsrv_result_int(struct ksql *p)
{
	enum ksqlc	 c, cc;
	struct ksqlstmt	*stmt;
	size_t		 col;
	int64_t		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;
	c = ksql_result_int(stmt, &val, col);
	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (ksql_result_isfatal(c))
		return c;

	/* Check code *before* writing result. */
	return ksql_writebuf(p, &val, sizeof(int64_t));
}

enum ksqlc
ksqlsrv_result_str(struct ksql *p)
{
	enum ksqlc	 c, cc;
	struct ksqlstmt	*stmt;
	size_t		 col;
	const char	*val = NULL;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;

	if (KSQL_OK == (c = ksql_result_check(stmt, col))) {
		val = (const char *)sqlite3_column_text(stmt->stmt, col);
		if (NULL == val)
			c = ksql_err(stmt->sql, KSQL_MEM, NULL);
	}

	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (ksql_result_isfatal(c))
		return c;

	/* Check code *before* writing result. */

	assert(NULL != val);
	return ksql_writestr(p, val);
}

enum ksqlc
ksql_result_isnull(struct ksqlstmt *stmt, int *p, size_t col)
{

 	*p = 0;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return ksql_readres(stmt, KSQLOP_RESULT_ISNULL, 
			col, p, sizeof(int));

	/*
	 * Do this differently from the others by not performing the
	 * SQLITE_NULL check.
	 * Eventually, the ksql_result_check() function will need to be
	 * modified so that it doesn't perform that one check for this
	 * function, else we'll end up duplicating code.
	 */

	if (col >= stmt->rcols) 
		return ksql_verr(stmt->sql, KSQL_RESULTCOL, 
			"result index %zu exceeds maximum "
			"index %zu", col, stmt->rcols - 1);

	if (SQLITE_NULL == sqlite3_column_type(stmt->stmt, col))
		*p = 1;

	return KSQL_OK;
}

enum ksqlc
ksql_result_bytes(struct ksqlstmt *stmt, size_t *p, size_t col)
{
	enum ksqlc	 c;

 	*p = 0;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return ksql_readres(stmt, KSQLOP_RESULT_BYTES, 
			col, p, sizeof(size_t));
	if (KSQL_OK == (c = ksql_result_check(stmt, col)))
		*p = sqlite3_column_bytes(stmt->stmt, col);

	return c;
}

enum ksqlc
ksql_result_double(struct ksqlstmt *stmt, double *p, size_t col)
{
	enum ksqlc	 c;

 	*p = 0.0;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return ksql_readres(stmt, KSQLOP_RESULT_DOUBLE, 
			col, p, sizeof(double));
	if (KSQL_OK == (c = ksql_result_check(stmt, col)))
		*p = sqlite3_column_double(stmt->stmt, col);

	return c;
}

enum ksqlc
ksql_result_int(struct ksqlstmt *stmt, int64_t *p, size_t col)
{
	enum ksqlc	 c;

 	*p = 0;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return ksql_readres(stmt, KSQLOP_RESULT_INT, 
			col, p, sizeof(int64_t));
	if (KSQL_OK == (c = ksql_result_check(stmt, col)))
		*p = sqlite3_column_int64(stmt->stmt, col);

	return c;
}

enum ksqlc
ksql_result_str(struct ksqlstmt *stmt, const char **p, size_t col)
{
	char		*cp = NULL;
	size_t		 sz;
	struct kcache	*cache;
	enum ksqlc	 c;

	*p = NULL;

	assert(KSQLSRV_ISPARENT(stmt->sql));

	c = ksql_readres
		(stmt, KSQLOP_RESULT_STR, 
		 col, &sz, sizeof(size_t));
	if (KSQL_OK != c)
		return c;

	if (NULL == (cp = malloc(sz + 1)))
		return ksql_err(stmt->sql, KSQL_MEM, NULL);
	cp[sz] = '\0';

	if (KSQL_OK != (c = ksql_readbuf(stmt->sql, cp, sz, 0))) {
		free(cp);
		return c;
	}

	if (NULL == (cache = calloc(1, sizeof(struct kcache)))) {
		free(cp);
		return ksql_err(stmt->sql, KSQL_MEM, NULL);
	}

	TAILQ_INSERT_TAIL(&stmt->cache, cache, entries);
	*p = cache->s = cp;
	return KSQL_OK;
}

enum ksqlc
ksql_result_str_alloc(struct ksqlstmt *stmt, char **p, size_t col)
{
	char		*cp = NULL;
	size_t		 sz;
	enum ksqlc	 c;

	*p = NULL;

	assert(KSQLSRV_ISPARENT(stmt->sql));

	c = ksql_readres
		(stmt, KSQLOP_RESULT_STR, 
		 col, &sz, sizeof(size_t));
	if (KSQL_OK != c)
		return c;

	if (NULL == (cp = malloc(sz + 1)))
		return ksql_err(stmt->sql, KSQL_MEM, NULL);
	cp[sz] = '\0';

	if (KSQL_OK != (c = ksql_readbuf(stmt->sql, cp, sz, 0))) {
		free(cp);
		return c;
	}

	*p = cp;
	return KSQL_OK;
}

enum ksqlc
ksql_result_blob(struct ksqlstmt *stmt, 
	const void **p, size_t *sz, size_t col)
{
	struct kcache	*cache;
	void		*cp = NULL;
	enum ksqlc	 c;
	size_t		 rsz;

	*p = NULL;
	*sz = 0;

	assert(KSQLSRV_ISPARENT(stmt->sql));

	c = ksql_readres
		(stmt, KSQLOP_RESULT_BLOB, 
		 col, &rsz, sizeof(size_t));
	if (KSQL_OK != c)
		return c;

	/* Don't allocate for zero-sized buffers. */

	if (0 == rsz)
		return KSQL_OK;
	if (NULL == (cp = malloc(rsz)))
		return ksql_err(stmt->sql, KSQL_MEM, NULL);

	if (KSQL_OK != (c = ksql_readbuf(stmt->sql, cp, rsz, 0))) {
		free(cp);
		return c;
	}

	if (NULL == (cache = calloc(1, sizeof(struct kcache)))) {
		free(cp);
		return ksql_err(stmt->sql, KSQL_MEM, NULL);
	}

	TAILQ_INSERT_TAIL(&stmt->cache, cache, entries);
	*p = cache->s = cp;
	*sz = rsz;
	return KSQL_OK;
}

enum ksqlc
ksql_result_blob_alloc(struct ksqlstmt *stmt, 
	void **p, size_t *sz, size_t col)
{
	enum ksqlc	 c;
	void		*cp;
	size_t		 rsz;

	*p = NULL;
	*sz = 0;

	assert(KSQLSRV_ISPARENT(stmt->sql));

	c = ksql_readres
		(stmt, KSQLOP_RESULT_BLOB, 
		 col, &rsz, sizeof(size_t));
	if (KSQL_OK != c)
		return c;

	/* Don't allocate for zero-sized buffers. */

	if (0 == rsz) 
		return KSQL_OK;
	if (NULL == (cp = malloc(rsz)))
		return ksql_err(stmt->sql, KSQL_MEM, NULL);

	if (KSQL_OK != (c = ksql_readbuf(stmt->sql, cp, rsz, 0))) {
		free(cp);
		return c;
	}

	*sz = rsz;
	*p = cp;
	return KSQL_OK;
}
