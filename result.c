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

#include <sys/queue.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include "ksql.h"
#include "extern.h"

/*
 * Make sure the result at column "col" is accessible to the current
 * statement.
 * Returns KSQL_OK if it is or an error otherwise.
 */
static enum ksqlc
ksql_result_check(struct ksqlstmt *stmt, size_t col)
{
	enum ksqlc	 c = KSQL_OK;

	if (col >= stmt->rcols) 
		c = ksql_verr(stmt->sql, KSQL_RESULTCOL, 
			"result index %zu exceeds maximum "
			"index %zu", col, stmt->rcols - 1);

	return c;
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
	if (KSQL_OK != code)
		return c;
	if (KSQL_OK != (c = ksql_readbuf(stmt->sql, buf, bufsz, 0)))
		return c;

	return KSQL_OK;
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
	else if (KSQL_OK != c)
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
	else if (KSQL_OK != c)
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
	else if (KSQL_OK != c)
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
	else if (KSQL_OK != c)
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
	const char	*val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)) ||
	    KSQL_OK != (c = ksql_readsz(p, &col)))
		return c;
	c = ksql_result_str(stmt, &val, col);
	if (KSQL_OK != (cc = ksql_writecode(p, c)))
		return cc;
	else if (KSQL_OK != c)
		return c;

	/* Check code *before* writing result. */
	return ksql_writestr(p, val);
}

enum ksqlc
ksql_result_isnull(struct ksqlstmt *stmt, int *p, size_t col)
{
	enum ksqlc	 c;

 	*p = 0;

	if (KSQLSRV_ISPARENT(stmt->sql))
		return ksql_readres(stmt, KSQLOP_RESULT_ISNULL, 
			col, p, sizeof(int));
	if (KSQL_OK == (c = ksql_result_check(stmt, col)))
		*p = SQLITE_NULL ==
			sqlite3_column_type(stmt->stmt, col);

	return c;
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

	if ( ! KSQLSRV_ISPARENT(stmt->sql)) {
		if (KSQL_OK == (c = ksql_result_check(stmt, col))) {
			*p = sqlite3_column_text(stmt->stmt, col);
			if (NULL == *p)
				c = ksql_err(stmt->sql, KSQL_MEM, NULL);
		}
		return c;
	}

	c = ksql_readres
		(stmt, KSQLOP_RESULT_STR, 
		 col, &sz, sizeof(size_t));
	if (KSQL_OK != c)
		return c;

	if (sz > 0) {
		if (NULL == (cp = malloc(sz)))
			return ksql_err(stmt->sql, KSQL_MEM, NULL);
		cp[sz - 1] = '\0';
		c = ksql_readbuf(stmt->sql, cp, sz - 1, 0);
		if (KSQL_OK != c) {
			free(cp);
			return c;
		}
	}

	if (NULL == (cache = calloc(1, sizeof(struct kcache)))) {
		free(cp);
		return ksql_err(stmt->sql, KSQL_MEM, NULL);
	}

	TAILQ_INSERT_TAIL(&stmt->cache, cache, entries);
	cache->s = cp;
	*p = cache->s;
	return KSQL_OK;
}
