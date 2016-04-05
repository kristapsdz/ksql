/*	$Id$ */
/*
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <sys/param.h>
#include <sys/queue.h>

#include <assert.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "ksql.h"

TAILQ_HEAD(ksqlstmtq, ksqlstmt);

/*
 * All of our current connections.
 * Modifications to this storage MUST be wrapped with ksql_jmp_start()
 * and ksql_jmp_end() to keep our longjmp wrapper consistent.
 */
TAILQ_HEAD(ksqlq, ksql) ksqls = 
	TAILQ_HEAD_INITIALIZER(ksqls);

/* 
 * Keep track of whether we've set any atexit(3) hooks for
 * KSQL_SAFE_EXIT handles, since we only want to do so once.
 */
static	int atexits;

/*
 * Our longjmp buffer, set in the critical section around "ksqls"
 * modifications if atexits is non-zero.
 */
static	sigjmp_buf jmpbuf;

/*
 * Whether our longjmp handler has been installed.
 * If so and we're in the signal handler, invoke the longjmp.
 */
static	volatile sig_atomic_t dojmp;

/*
 * Holder for SQLite statements.
 */
struct	ksqlstmt {
	sqlite3_stmt		*stmt;
	size_t			 id;
	struct ksql		*sql;
	TAILQ_ENTRY(ksqlstmt) 	 entries;
};

/*
 * Holds all information about open connections.
 */
struct	ksql {
	struct ksqlcfg	 	 cfg;
	sqlite3			*db;
	char			*dbfile;
	struct ksqlstmtq	 stmt_used;
	struct ksqlstmtq	 stmt_free;
	unsigned int		 flags;
#define	KSQLFL_TRANS		 0x01 /* trans is open */
	TAILQ_ENTRY(ksql)	 entries;
};

static	const char * const ksqlcs[] = {
	NULL, /* KSQL_OK */
	NULL, /* KSQL_DONE */
	NULL, /* KSQL_ROW */
	NULL, /* KSQL_CONSTRAINT */
	"memory exhausted", /* KSQL_MEM */
	"database not open", /* KSQL_NOTOPEN */
	"database error", /* KSQL_DB */
	"transaction already open or not yet open", /* KSQL_TRANS */
	"statement(s) open on exit", /* KSQL_STMT */
	"closing on exit", /* KSQL_EXIT */
};

static enum ksqlc ksql_free_inner(struct ksql *, int);

/*
 * This is called within an atexit(3) handler for connections specified
 * with KSQL_SAFE_FAIL.
 * It suppresses KSQL_EXIT_ON_ERR and the longjmp buffer, then closes
 * out all resources.
 */
static void
ksql_atexit(void)
{
	struct ksql	*p;

	atexits = 0;
	dojmp = 0;

	while ( ! TAILQ_EMPTY(&ksqls)) {
		p = TAILQ_FIRST(&ksqls);
		/*
		 * We're already exiting, so don't let any of the
		 * interior functions bail us out again.
		 */
		p->cfg.flags &= ~KSQL_EXIT_ON_ERR;
		ksql_free_inner(p, 1);
	}
}

static void
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
static enum ksqlc
ksql_err(struct ksql *p, enum ksqlc erc, const char *msg)
{

	ksql_err_noexit(p, erc, msg);
	if (KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);
	return(erc);
}

static void
ksql_dberr_noexit(struct ksql *p)
{

	if (NULL != p->cfg.dberr)
		p->cfg.dberr(p->cfg.arg, 
			sqlite3_errcode(p->db),
			sqlite3_extended_errcode(p->db),
			p->dbfile,
			sqlite3_errmsg(p->db));
}

/*
 * Pass an error to the error handler, if found.
 * Then if we're exiting on errors, do it here.
 */
static enum ksqlc
ksql_dberr(struct ksql *p)
{

	ksql_dberr_noexit(p);
	if (KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);
	return(KSQL_DB);
}

static void
sqlitedbmsg(void *arg, int sql3, int esql3, const char *file, const char *msg)
{

	(void)arg;
	fprintf(stderr, "%s: %s: %s (%d, %d)\n",
		getprogname(), file, msg, sql3, esql3);
}

static void
sqlitemsg(void *arg, enum ksqlc code, const char *file, const char *msg)
{

	(void)arg;
	if (NULL != file)
		fprintf(stderr, "%s: %s: %s (%d)\n", 
			getprogname(), file, msg, code);
	else
		fprintf(stderr, "%s: %s (%d)\n", 
			getprogname(), msg, code);
}

/*
 * This is a way for us to sleep between connection attempts.
 * To reduce lock contention, our sleep will be random.
 * We use a deterministic RNG which we'll seed at initialisation.
 */
static void
ksql_sleep(size_t attempt)
{
	useconds_t	us;

	us = attempt > 100 ? 10000 :  /* 1/100 second */
	     attempt > 10  ? 100000 : /* 1/10 second */
	     250000;                  /* 1/4 second */

	usleep(us * (double)(random() / (double)RAND_MAX));
}

static enum ksqlc
ksql_exec_inner(struct ksql *p, const char *sql)
{
	size_t	attempt = 0;
	int	rc;

	if (NULL == p->db)
		return(KSQL_NOTOPEN);
again:
	rc = sqlite3_exec(p->db, sql, NULL, NULL, NULL);

	if (SQLITE_BUSY == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_LOCKED == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_PROTOCOL == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_OK == rc)
		return(KSQL_OK);

	return(KSQL_DB);
}

/*
 * Signal handler to be used if a connection has specified
 * KSQL_SAFE_FAIL and we're interrupted by a bad signal.
 * We only act if "dojmp" has been set, that is, if we're not in a
 * critical section.
 */
static void
ksql_signal(int code)
{

	if (dojmp) {
		dojmp = 0;
		siglongjmp(jmpbuf, code);
	} else 
		dojmp = 0;
}

/*
 * Start a critical section that modifies "ksqls".
 * This must be matched by ksql_jmp_end();
 * Within a critical section, our longjmp buffer is disabled because the
 * automatic storage we'd modify is in flux.
 */
static void
ksql_jmp_start(void)
{

	dojmp = 0;
}

/*
 * See ksql_jmp_start().
 */
static void
ksql_jmp_end(void)
{

	/* Only run this if our exit handler is valid. */
	if ( ! atexits)
		return;

	/* Restore jump buffer. */
	if (sigsetjmp(jmpbuf, 1))
		exit(EXIT_FAILURE);
	dojmp = 1;
}

struct ksql *
ksql_alloc(const struct ksqlcfg *cfg)
{
	struct ksql	*p;

	p = calloc(1, sizeof(struct ksql));
	if (NULL == p)
		return(NULL);

	if (NULL == cfg) {
		/*
		 * Make some safe defaults here.
		 * Specifically, log all of our database and `soft'
		 * errors to stderr and make us bail on exit, as well
		 * trying to catch signals/exits.
		 */
		p->cfg.dberr = sqlitedbmsg;
		p->cfg.err = sqlitemsg;
		p->cfg.flags = KSQL_EXIT_ON_ERR | KSQL_SAFE_EXIT;
	} else
		p->cfg = *cfg;

	/*
	 * If we're going to exit on failure, then automatically
	 * register this to be cleaned up if we do exit.
	 */
	if (KSQL_SAFE_EXIT & p->cfg.flags) {
		/* 
		 * Only do this once to prevent us from running out of
		 * atexit(3) calls (we're limited).
		 */
		if (0 == atexits) {
			if (-1 == atexit(ksql_atexit)) {
				free(p);
				return(NULL);
			}
			atexits = 1;
			/* 
			 * Note: we don't set dojmp until after
			 * ksql_jmp_end(), so our jump buffer won't get
			 * invoked yet. 
			 */
			signal(SIGABRT, ksql_signal);
			signal(SIGSEGV, ksql_signal);
		}
		ksql_jmp_start();
		TAILQ_INSERT_TAIL(&ksqls, p, entries);
		ksql_jmp_end();
	}

	srandom(arc4random());

	TAILQ_INIT(&p->stmt_used);
	TAILQ_INIT(&p->stmt_free);
	return(p);
}

static enum ksqlc 
ksql_close_inner(struct ksql *p, int onexit)
{
	struct ksqlstmt	*stmt;
	char		 buf[PATH_MAX];
	enum ksqlc	 haserrs;
	enum ksqlc	 c;

	haserrs = KSQL_OK;

	/* Short-circuit. */
	if (NULL == p || NULL == p->db)
		return(KSQL_OK);

	if (onexit)
		ksql_err_noexit(p, KSQL_EXIT, NULL);

	/* 
	 * Finalise out all open statements first. 
	 * Don't run ksql_err() yet because it will kill the process
	 * and we want to free these now.
	 */
	while ( ! TAILQ_EMPTY(&p->stmt_used)) {
		stmt = TAILQ_FIRST(&p->stmt_used);
		TAILQ_REMOVE(&p->stmt_used, stmt, entries);
		sqlite3_finalize(stmt->stmt);
		snprintf(buf, sizeof(buf),
			"statement %zu still open", stmt->id);
		stmt->stmt = NULL;
		TAILQ_INSERT_TAIL(&p->stmt_free, stmt, entries);
		haserrs = KSQL_STMT;
		ksql_err_noexit(p, KSQL_STMT, buf);
	}

	/* 
	 * A transaction is open on exit.
	 * Close it and unset the notification.
	 */
	if (KSQLFL_TRANS & p->flags) {
		haserrs = KSQL_TRANS;
		p->flags &= ~KSQLFL_TRANS;
		/* (We know we won't have KSQL_NOTOPEN.) */
		c = ksql_exec_inner(p, "ROLLBACK TRANSACTION");
		if (KSQL_DB == c) {
			ksql_dberr_noexit(p);
			haserrs = KSQL_DB;
		}
	}

	/* Now try to close the database itself. */
	if (SQLITE_OK != sqlite3_close(p->db)) {
		ksql_dberr_noexit(p);
		haserrs = KSQL_DB;
	}

	free(p->dbfile);
	p->dbfile = NULL;
	p->db = NULL;

	/* Delay our exit check til now. */
	if (haserrs && KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);
	return(haserrs);
}

enum ksqlc 
ksql_close(struct ksql *p)
{

	return(ksql_close_inner(p, 0));
}

static enum ksqlc
ksql_free_inner(struct ksql *p, int onexit)
{
	struct ksqlstmt	*stmt;
	enum ksqlc	 er;

	if (NULL == p)
		return(KSQL_OK);

	er = ksql_close_inner(p, onexit);
	while ( ! TAILQ_EMPTY(&p->stmt_free)) {
		stmt = TAILQ_FIRST(&p->stmt_free);
		TAILQ_REMOVE(&p->stmt_free, stmt, entries);
		assert(NULL == stmt->stmt);
		free(stmt);
		stmt = NULL;
	}

	if (KSQL_SAFE_EXIT & p->cfg.flags) {
		ksql_jmp_start();
		TAILQ_REMOVE(&ksqls, p, entries);
		ksql_jmp_end();
	}

	free(p);
	return(er);
}

enum ksqlc
ksql_free(struct ksql *p)
{

	return(ksql_free_inner(p, 0));
}

enum ksqlc
ksql_exec(struct ksql *p, const char *sql, size_t id)
{
	enum ksqlc	c;

	(void)id; /* FOR NOW */

	c = ksql_exec_inner(p, sql);
	if (KSQL_DB == c)
		return(ksql_dberr(p));
	else if (KSQL_NOTOPEN == c)
		return(ksql_err(p, c, NULL));

	return(KSQL_OK);
}

enum ksqlc
ksql_open(struct ksql *p, const char *dbfile)
{
	size_t		 attempt = 0;
	int		 rc;
	enum ksqlc	 er;

	/* Close out any existing open database. */
	if (NULL != p->db) 
		if (KSQL_OK != (er = ksql_close(p)))
			return(er);

	if (NULL == (p->dbfile = strdup(dbfile)))
		return(ksql_err(p, KSQL_MEM, NULL));
again:
	rc = sqlite3_open(dbfile, &p->db);

	if (SQLITE_BUSY == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_LOCKED == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_PROTOCOL == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_OK != rc) 
		return(ksql_dberr(p));

	/* Handle required foreign key invocation. */
	return(KSQL_FOREIGN_KEYS & p->cfg.flags ?
		ksql_exec(p, "PRAGMA foreign_keys = ON;", SIZE_MAX) :
		KSQL_OK);
}

static enum ksqlc
ksql_step_inner(struct ksqlstmt *stmt, int cstr)
{
	int	 rc;
	size_t	 attempt = 0;

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
again:
	rc = sqlite3_step(stmt->stmt);
	if (SQLITE_BUSY == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_LOCKED == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_PROTOCOL == rc) {
		ksql_sleep(attempt++);
		goto again;
	}

	if (SQLITE_DONE == rc)
		return(KSQL_DONE);
	if (SQLITE_ROW == rc)
		return(KSQL_ROW);

	if (SQLITE_CONSTRAINT == rc && cstr)
		return(KSQL_CONSTRAINT);
	return(ksql_dberr(stmt->sql));
}

void
ksql_stmt_reset(struct ksqlstmt *stmt)
{

	sqlite3_reset(stmt->stmt);
}

enum ksqlc
ksql_stmt_step(struct ksqlstmt *stmt)
{

	return(ksql_step_inner(stmt, 0));
}

enum ksqlc
ksql_stmt_cstep(struct ksqlstmt *stmt)
{

	return(ksql_step_inner(stmt, 1));
}

void
ksql_stmt_free(struct ksqlstmt *stmt)
{

	sqlite3_finalize(stmt->stmt);
	stmt->stmt = NULL;
	TAILQ_REMOVE(&stmt->sql->stmt_used, stmt, entries);
	TAILQ_INSERT_TAIL(&stmt->sql->stmt_free, stmt, entries);
}

enum ksqlc
ksql_stmt_alloc(struct ksql *p, 
	struct ksqlstmt **stmt, const char *sql, size_t id)
{
	struct ksqlstmt	*ss;
	size_t		 attempt = 0;
	sqlite3_stmt 	*st;
	int		 rc;

	*stmt = NULL;

	/*
	 * If we don't have any spare statements to draw from, allocate
	 * one now before investing in the statement preparation.
	 */
	if (TAILQ_EMPTY(&p->stmt_free)) {
		ss = calloc(1, sizeof(struct ksqlstmt));
		if (NULL == ss)
			return(ksql_err(p, KSQL_MEM, NULL));
		TAILQ_INSERT_TAIL(&p->stmt_free, ss, entries);
	} 
	
	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
again:
	rc = sqlite3_prepare_v2(p->db, sql, -1, &st, NULL);

	if (SQLITE_BUSY == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_LOCKED == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_PROTOCOL == rc) {
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_OK != rc) {
		return(ksql_dberr(p));
	}

	/*
	 * Draw an unused statement container from the queue (we made
	 * one above if there were now) and fill it here.
	 */
	ss = TAILQ_FIRST(&p->stmt_free);
	assert(NULL != ss);
	ss->stmt = st;
	ss->id = id;
	ss->sql = p;
	TAILQ_REMOVE(&p->stmt_free, ss, entries);
	TAILQ_INSERT_TAIL(&p->stmt_used, ss, entries);
	*stmt = ss;
	return(KSQL_OK);
}

enum ksqlc
ksql_bind_zblob(struct ksqlstmt *stmt, size_t pos, size_t valsz)
{
	int	 rc;

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

	rc = sqlite3_bind_blob(stmt->stmt, 
		pos + 1, val, valsz, SQLITE_STATIC);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_str(struct ksqlstmt *stmt, size_t pos, const char *val)
{
	int	 rc;

	rc = sqlite3_bind_text(stmt->stmt, pos + 1, val, -1, SQLITE_STATIC);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_double(struct ksqlstmt *stmt, size_t pos, double val)
{
	int	 rc;

	rc = sqlite3_bind_double(stmt->stmt, pos + 1, val);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_null(struct ksqlstmt *stmt, size_t pos)
{

	if (SQLITE_OK == sqlite3_bind_null(stmt->stmt, pos + 1))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_int(struct ksqlstmt *stmt, size_t pos, int64_t val)
{

	if (SQLITE_OK == sqlite3_bind_int64(stmt->stmt, pos + 1, val))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

static enum ksqlc
ksql_trans_close_inner(struct ksql *p, int rollback)
{
	enum ksqlc	 c;

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
	if ( ! (KSQLFL_TRANS & p->flags))
		return(KSQL_TRANS);
	c = rollback ?
		ksql_exec(p, "ROLLBACK TRANSACTION", SIZE_MAX) :
		ksql_exec(p, "COMMIT TRANSACTION", SIZE_MAX);
	/* Set this only if the exec succeeded.*/
	if (KSQL_OK == c)
		p->flags &= ~KSQLFL_TRANS;
	return(c);
}

static enum ksqlc
ksql_trans_open_inner(struct ksql *p, int immediate)
{
	enum ksqlc	 c;

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
	if (KSQLFL_TRANS & p->flags) 
		return(KSQL_TRANS);

	c = immediate ? 
		ksql_exec(p, "BEGIN IMMEDIATE", SIZE_MAX) : 
		ksql_exec(p, "BEGIN TRANSACTION", SIZE_MAX);
	/* Set this only if the exec succeeded.*/
	if (KSQL_OK == c)
		p->flags |= KSQLFL_TRANS;
	return(c);
}

enum ksqlc
ksql_trans_open(struct ksql *p)
{

	return(ksql_trans_open_inner(p, 0));
}

enum ksqlc
ksql_trans_exclopen(struct ksql *p)
{

	return(ksql_trans_open_inner(p, 1));
}

enum ksqlc
ksql_trans_commit(struct ksql *p)
{

	return(ksql_trans_close_inner(p, 0));
}

enum ksqlc
ksql_trans_rollback(struct ksql *p)
{

	return(ksql_trans_close_inner(p, 1));
}

enum ksqlc
ksql_lastid(struct ksql *p, int64_t *id)
{

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
	if (NULL != id)
		*id = sqlite3_last_insert_rowid(p->db);
	return(KSQL_OK);
}

const void *
ksql_stmt_blob(struct ksqlstmt *stmt, size_t col)
{

	return(sqlite3_column_blob(stmt->stmt, (int)col));
}

size_t
ksql_stmt_bytes(struct ksqlstmt *stmt, size_t col)
{

	return((size_t)sqlite3_column_bytes(stmt->stmt, (int)col));
}

double
ksql_stmt_double(struct ksqlstmt *stmt, size_t col)
{

	return(sqlite3_column_double(stmt->stmt, (int)col));
}

int64_t
ksql_stmt_int(struct ksqlstmt *stmt, size_t col)
{

	return(sqlite3_column_int64(stmt->stmt, (int)col));
}

char *
ksql_stmt_str(struct ksqlstmt *stmt, size_t col)
{

	return((char *)sqlite3_column_text(stmt->stmt, (int)col));
}
