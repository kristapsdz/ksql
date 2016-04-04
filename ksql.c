/*	$Id$ */
#include <sys/queue.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "ksql.h"

TAILQ_HEAD(ksqlstmtq, ksqlstmt);

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
#define	KSQL_TRANS		 0x01 /* trans is open */
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
	"statement open on exit", /* KSQL_STMT */
};

/*
 * See ksql_dberr().
 */
static enum ksqlc
ksql_err(struct ksql *p, enum ksqlc erc, const char *msg)
{

	if (NULL == msg)
		msg = ksqlcs[erc];
	assert(NULL != msg);

	if (NULL != p->cfg.err)
		p->cfg.err(p->cfg.arg, erc, msg);

	/* Byeeee... */
	if (KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);

	return(erc);
}

/*
 * Pass an error to the error handler, if found.
 * Then if we're exiting on errors, do it here.
 */
static enum ksqlc
ksql_dberr(struct ksql *p)
{

	if (NULL != p->cfg.dberr)
		p->cfg.dberr(p->cfg.arg, 
			sqlite3_errcode(p->db),
			sqlite3_extended_errcode(p->db),
			p->dbfile,
			sqlite3_errmsg(p->db));

	/* Byeeee... */
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
sqlitemsg(void *arg, enum ksqlc code, const char *msg)
{

	(void)arg;
	fprintf(stderr, "%s: %s (%d)\n", getprogname(), msg, code);
}

struct ksql *
ksql_alloc(const struct ksqlcfg *cfg)
{
	struct ksql	*p;

	p = calloc(1, sizeof(struct ksql));
	if (NULL == p)
		return(NULL);

	if (NULL == cfg) {
		p->cfg.dberr = sqlitedbmsg;
		p->cfg.err = sqlitemsg;
		p->cfg.flags = KSQL_EXIT_ON_ERR;
	} else
		p->cfg = *cfg;

	srandom(arc4random());

	TAILQ_INIT(&p->stmt_used);
	TAILQ_INIT(&p->stmt_free);
	return(p);
}

enum ksqlc 
ksql_close(struct ksql *p)
{
	struct ksqlstmt	*stmt;
	char		 buf[64];

	if (NULL == p || NULL == p->db)
		return(KSQL_OK);

	free(p->dbfile);
	p->dbfile = NULL;

	while ( ! TAILQ_EMPTY(&p->stmt_used)) {
		stmt = TAILQ_FIRST(&p->stmt_used);
		TAILQ_REMOVE(&p->stmt_used, stmt, entries);
		sqlite3_finalize(stmt->stmt);
		snprintf(buf, sizeof(buf),
			"statement %zu still open",
			stmt->id);
		stmt->stmt = NULL;
		TAILQ_INSERT_TAIL(&p->stmt_free, stmt, entries);
		if (NULL != p->cfg.err)
			p->cfg.err(p->cfg.arg, KSQL_STMT, buf);
	}

	if (SQLITE_OK != sqlite3_close(p->db))
		return(ksql_dberr(p));

	p->db = NULL;
	return(KSQL_OK);
}

enum ksqlc
ksql_free(struct ksql *p)
{
	struct ksqlstmt	*stmt;
	enum ksqlc	 er;

	if (NULL == p)
		return(KSQL_OK);

	er = ksql_close(p);
	while ( ! TAILQ_EMPTY(&p->stmt_free)) {
		stmt = TAILQ_FIRST(&p->stmt_free);
		TAILQ_REMOVE(&p->stmt_free, stmt, entries);
		assert(NULL == stmt->stmt);
		free(stmt);
		stmt = NULL;
	}
	free(p);
	return(er);
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

enum ksqlc
ksql_exec(struct ksql *p, const char *sql, size_t id)
{
	size_t	attempt = 0;
	int	rc;

	(void)id; /* FOR NOW */

	if (NULL == p->db)
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
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

	return(ksql_dberr(p));
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

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
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

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
	rc = sqlite3_bind_blob(stmt->stmt, 
		pos + 1, val, valsz, SQLITE_STATIC);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_text(struct ksqlstmt *stmt, size_t pos, const char *val)
{
	int	 rc;

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
	rc = sqlite3_bind_text(stmt->stmt, pos + 1, val, -1, SQLITE_STATIC);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_double(struct ksqlstmt *stmt, size_t pos, double val)
{
	int	 rc;

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
	rc = sqlite3_bind_double(stmt->stmt, pos + 1, val);
	if (SQLITE_OK == rc)
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_null(struct ksqlstmt *stmt, size_t pos)
{

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
	if (SQLITE_OK == sqlite3_bind_null(stmt->stmt, pos + 1))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

enum ksqlc
ksql_bind_int(struct ksqlstmt *stmt, size_t pos, int64_t val)
{

	if (NULL == stmt->sql->db) 
		return(ksql_err(stmt->sql, KSQL_NOTOPEN, NULL));
	if (SQLITE_OK == sqlite3_bind_int64(stmt->stmt, pos + 1, val))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

static enum ksqlc
ksql_trans_open_inner(struct ksql *p, int immediate)
{

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
	if (KSQL_TRANS & p->flags) 
		return(KSQL_TRANS);

	p->flags |= KSQL_TRANS;
	return(immediate ? 
		ksql_exec(p, "BEGIN IMMEDIATE", SIZE_MAX) : 
		ksql_exec(p, "BEGIN TRANSACTION", SIZE_MAX));
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

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
	if ( ! (KSQL_TRANS & p->flags))
		return(KSQL_TRANS);
	return(ksql_exec(p, "COMMIT TRANSACTION", SIZE_MAX));
}

enum ksqlc
ksql_trans_rollback(struct ksql *p)
{

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
	if ( ! (KSQL_TRANS & p->flags))
		return(KSQL_TRANS);
	return(ksql_exec(p, "ROLLBACK TRANSACTION", SIZE_MAX));
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
