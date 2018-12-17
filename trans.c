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

static enum ksqlc
ksql_trans_close_inner(struct ksql *p, size_t mode, size_t id)
{
	enum ksqlc	 c, cc;
	char	 	 buf[1024];

	if (KSQLSRV_ISPARENT(p)) {
		c = ksql_writeop(p, KSQLOP_TRANS_CLOSE);
		if (KSQL_OK != c)
			return c;
		if (KSQL_OK != (c = ksql_writesz(p, mode))) 
			return c;
		if (KSQL_OK != (c = ksql_writesz(p, id)))
			return c;
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return c;
		return cc;
	}

	if (NULL == p->db) 
		return ksql_err(p, KSQL_NOTOPEN, NULL);

	if ( ! (KSQLFL_TRANS & p->flags)) {
		snprintf(buf, sizeof(buf),
			"transaction %zu not open", id);
		return ksql_err(p, KSQL_TRANS, buf);
	} else if (id != p->trans) {
		snprintf(buf, sizeof(buf),
			"transaction %zu pending on close of %zu", 
			p->trans, id);
		return ksql_err(p, KSQL_TRANS, buf);
	}

	c = mode ?
		ksql_exec_private(p, "ROLLBACK TRANSACTION") :
		ksql_exec_private(p, "COMMIT TRANSACTION");

	/* Set this only if the exec succeeded.*/

	if (KSQL_OK == c)
		p->flags &= ~KSQLFL_TRANS;

	return c;
}

static enum ksqlc
ksql_trans_open_inner(struct ksql *p, size_t mode, size_t id)
{
	enum ksqlc	 c, cc;
	char		 buf[1024];

	if (KSQLSRV_ISPARENT(p)) {
		c = ksql_writeop(p, KSQLOP_TRANS_OPEN);
		if (KSQL_OK != c)
			return c;
		if (KSQL_OK != (c = ksql_writesz(p, mode))) 
			return c;
		if (KSQL_OK != (c = ksql_writesz(p, id)))
			return c;
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return c;
		return cc;
	}

	if (NULL == p->db) 
		return ksql_err(p, KSQL_NOTOPEN, NULL);

	if (KSQLFL_TRANS & p->flags) {
		snprintf(buf, sizeof(buf),
			"transaction %zu still open", p->trans);
		return ksql_err(p, KSQL_TRANS, buf);
	}

	assert(mode <= 2);

	if (2 == mode)
		c = ksql_exec_private(p, "BEGIN EXCLUSIVE");
	else if (1 == mode)
		c = ksql_exec_private(p, "BEGIN IMMEDIATE");
	else
		c = ksql_exec_private(p, "BEGIN DEFERRED");

	/* Set this only if the exec succeeded.*/

	if (KSQL_OK == c) {
		p->flags |= KSQLFL_TRANS;
		p->trans = id;
	}
	return c;
}

enum ksqlc
ksqlsrv_trans_close(struct ksql *p)
{
	enum ksqlc	 c, cc;
	size_t		 type, id;

	if (KSQL_OK != (c = ksql_readsz(p, &type)))
		return c;
	if (KSQL_OK != (c = ksql_readsz(p, &id)))
		return c;
	cc = ksql_trans_close_inner(p, type, id);
	return ksql_writecode(p, cc);
}

enum ksqlc
ksqlsrv_trans_open(struct ksql *p)
{
	enum ksqlc	 c, cc;
	size_t		 type, id;

	if (KSQL_OK != (c = ksql_readsz(p, &type)))
		return c;
	if (KSQL_OK != (c = ksql_readsz(p, &id)))
		return c;
	cc = ksql_trans_open_inner(p, type, id);
	return ksql_writecode(p, cc);
}

enum ksqlc
ksql_trans_open(struct ksql *p, size_t id)
{

	return ksql_trans_open_inner(p, 0, id);
}

enum ksqlc
ksql_trans_exclopen(struct ksql *p, size_t id)
{

	return ksql_trans_open_inner(p, 2, id);
}

enum ksqlc
ksql_trans_singleopen(struct ksql *p, size_t id)
{

	return ksql_trans_open_inner(p, 1, id);
}

enum ksqlc
ksql_trans_commit(struct ksql *p, size_t id)
{

	return ksql_trans_close_inner(p, 0, id);
}

enum ksqlc
ksql_trans_rollback(struct ksql *p, size_t id)
{

	return ksql_trans_close_inner(p, 1, id);
}
