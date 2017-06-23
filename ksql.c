/*	$Id$ */
/*
 * Copyright (c) 2016--2017 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <sys/socket.h>
#include <sys/wait.h>

#include <err.h> /* XXX: debugging */

#include <assert.h>
#include <errno.h>
#include <inttypes.h> /* XXX: debugging */
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __linux__
# include <bsd/stdlib.h>
#endif
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "ksql.h"

TAILQ_HEAD(ksqlstmtq, ksqlstmt);

/*
 * All of our current connections.
 * Modifications to this storage MUST be wrapped with ksql_jmp_start()
 * and ksql_jmp_end() to keep our exit routines consistent.
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
 * Holder for pending SQLite statements.
 * If we exit out of state, we'll finalise these statements.
 */
struct	ksqlstmt {
	sqlite3_stmt		*stmt; /* statement */
	size_t			 id; /* its identifier */
	struct ksql		*sql; /* corresponding db */
	void			*ptr; /* daemon mode pointer */
	TAILQ_ENTRY(ksqlstmt) 	 entries;
};

/*
 * When running in client-server mode, this holds information about the
 * process on the other end of our socket.
 * If the "pid" is 0, then we're connected to the parent (i.e., we're
 * the child); if it's non-zero, we're the parent.
 */
struct	ksqld {
	pid_t	 pid; /* other process of socket */
	int	 fd; /* -1 on init */
};

/*
 * Holds all information about open connections.
 * In client-server mode, this holds a "daemon" field used to
 * communicate with the other end of the connection.
 */
struct	ksql {
	struct ksqlcfg	 	 cfg;
	sqlite3			*db;
	char			*dbfile; /* fname of db */
	struct ksqlstmtq	 stmt_used; /* used list */
	struct ksqlstmtq	 stmt_free; /* free list */
	size_t			 trans; /* current transactions */
	struct ksqld		*daemon; /* if applicable */
	unsigned int		 flags;
#define	KSQLFL_TRANS		 0x01 /* trans is open */
	TAILQ_ENTRY(ksql)	 entries;
};

#define	KSQLSRV_ISPARENT(_p) \
	(NULL != (_p)->daemon && (_p)->daemon->pid)
#define	KSQLSRV_ISCHILD(_p) \
	(NULL != (_p)->daemon && 0 == (_p)->daemon->pid)

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
	"database error", /* KSQL_DB */
	"transaction already open or not yet open", /* KSQL_TRANS */
	"statement(s) open on exit", /* KSQL_STMT */
	"closing on exit", /* KSQL_EXIT */
	"system error", /* KSQL_SYSTEM */
	NULL, /* KSQL_EOF */
};

/*
 * Operation code used to communicate between client-server.
 */
enum	ksqlop {
	KSQLOP_BIND_BLOB, /* ksql_bind_blob */
	KSQLOP_BIND_DOUBLE, /* ksql_bind_double */
	KSQLOP_BIND_INT, /* ksql_bind_int */
	KSQLOP_BIND_NULL, /* ksql_bind_null */  
	KSQLOP_BIND_TEXT, /* ksql_bind_text */  
	KSQLOP_BIND_ZBLOB, /* ksql_bind_zblob */
	KSQLOP_CLOSE, /* ksql_close */
	KSQLOP_COL_BYTES, /* ksql_stmt_bytes */
	KSQLOP_COL_DOUBLE, /* ksql_stmt_double */
	KSQLOP_COL_INT, /* ksql_stmt_int */
	KSQLOP_COL_ISNULL, /* ksql_stmt_isnull */
	KSQLOP_OPEN, /* ksql_open */
	KSQLOP_STMT_ALLOC, /* ksql_stmt_alloc */
	KSQLOP_STMT_FREE, /* ksql_stmt_free */
	KSQLOP_STMT_RESET, /* ksql_stmt_reset */
	KSQLOP_STMT_STEP, /* ksql_stmt_step */
};

static	const char *const ksqlops[] = {
	"BIND_BLOB", /* KSQLOP_BIND_BLOB */
	"BIND_DOUBLE", /* KSQLOP_BIND_DOUBLE */
	"BIND_INT", /* KSQLOP_BIND_INT */
	"BIND_NULL", /* KSQLOP_BIND_NULL */
	"BIND_TEXT", /* KSQLOP_BIND_TEXT */
	"BIND_ZBLOB", /* KSQLOP_BIND_ZBLOB */
	"CLOSE", /* KSQLOP_CLOSE */
	"COL_BYTES", /* KSQLOP_COL_BYTES */
	"COL_DOUBLE", /* KSQLOP_COL_DOUBLE */
	"COL_INT", /* KSQLOP_COL_INT */
	"COL_ISNULL", /* KSQLOP_COL_ISNULL */
	"OPEN", /* KSQLOP_OPEN */
	"STMT_ALLOC", /* KSQLOP_STMT_ALLOC */
	"STMT_FREE", /* KSQLOP_STMT_FREE */
	"STMT_RESET", /* KSQLOP_STMT_RESET */
	"STMT_STEP", /* KSQLOP_STMT_STEP */
};

/*
 * Forward declarations.
 */
static enum ksqlc ksql_free_inner(struct ksql *, int);
static enum ksqlc ksql_step_inner(struct ksqlstmt *, size_t);

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

	warnx(__func__);

	atexits = 0;
	dojmp = 0;

	while ( ! TAILQ_EMPTY(&ksqls)) {
		p = TAILQ_FIRST(&ksqls);
		warnx("%s: killing: %p", __func__, p);
		/*
		 * We're already exiting, so don't let any of the
		 * interior functions bail us out again.
		 */
		p->cfg.flags &= ~KSQL_EXIT_ON_ERR;
		ksql_free_inner(p, 1);
	}
}

/*
 * If there's an error function, use it to print "msg".
 * Don't do anything else (i.e., don't exit).
 * This can be used to simply print errors and messages.
 * Does nothing if there's no error handler.
 */
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

/*
 * Pass a database error from SQLite to the error printing function.
 * If no database error has occurred, this will print something
 * harmless.
 * Does nothing if there's no database-error handler.
 */
static void
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
static enum ksqlc
ksql_dberr(struct ksql *p)
{

	ksql_dberr_noexit(p);
	if (KSQL_EXIT_ON_ERR & p->cfg.flags)
		exit(EXIT_FAILURE);
	return(KSQL_DB);
}

void
ksql_trace(struct ksql *p)
{

	sqlite3_config(SQLITE_CONFIG_LOG, ksql_tracemsg, p);
}

void
ksql_untrace(void)
{

	sqlite3_config(SQLITE_CONFIG_LOG, NULL, NULL);
}

void
ksqlitedbmsg(void *arg, int sql3, 
	int esql3, const char *file, const char *msg)
{

	(void)arg;
	fprintf(stderr, "%s: %s: %s (error code %d, extended %d)\n",
		getprogname(), file, msg, sql3, esql3);
}

void
ksqlitemsg(void *arg, enum ksqlc code, const char *file, const char *msg)
{

	(void)arg;
	if (NULL != file)
		fprintf(stderr, "%s: %s: %s (error code %d)\n", 
			getprogname(), file, msg, code);
	else
		fprintf(stderr, "%s: %s (error code %d)\n", 
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

/*
 * Directly execute "sql" forever.
 * If we lock or are busy, back off randomly and try again.
 */
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

/*
 * Read buffer "buf" of size "sz" from the daemon connection, which is
 * assumed to be a non-blocking descriptor.
 * (The daemon connection must be valid.)
 * On success (all "sz" bytes read), return KSQL_OK.
 * Otherwise, invoke ksql_err() with the given error code.
 */
static enum ksqlc
ksql_readbuf(struct ksql *p, void *buf, size_t sz, int eofok)
{
	struct pollfd	 pfd;
	ssize_t	 	 ssz;
	size_t		 rsz = 0;
	int		 rc;
	const char	*msg;

	assert(NULL != p->daemon);
	assert(-1 != p->daemon->fd);

	memset(&pfd, 0, sizeof(struct pollfd));

	pfd.fd = p->daemon->fd;
	pfd.events = POLLIN;

	while (rsz < sz) {
		if ((rc = poll(&pfd, 1, INFTIM)) < 0) {
			msg = strerror(errno);
			return(ksql_err(p, KSQL_SYSTEM, msg));
		} else if (0 == rc) {
			/* This shouldn't happen. */
			msg = "poll reader timeout!?";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		}

		if (POLLIN & pfd.revents) {
			ssz = read(pfd.fd, buf + rsz, sz - rsz);
			if (ssz < 0) {
				msg = strerror(errno);
				return(ksql_err(p, KSQL_SYSTEM, msg));
			}
			rsz += (size_t)ssz;
		}

		/* Errors in poll? */

		if (POLLHUP & pfd.revents && eofok)
			return(KSQL_EOF);

		if (POLLHUP & pfd.revents) {
			msg = "poll hup";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		} else if (POLLERR & pfd.revents) {
			msg = "poll error";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		} 
	}

	return(KSQL_OK);
}

/*
 * Read a scalar operation "op" from the connection in "p".
 * See ksql_readbuf().
 */
static enum ksqlc
ksql_readop(struct ksql *p, enum ksqlop *op)
{

	return(ksql_readbuf(p, op, sizeof(enum ksqlop), 1));
}

/*
 * Read a scalar size "sz" from the connection in "p".
 * See ksql_readbuf().
 */
static enum ksqlc
ksql_readpos(struct ksql *p, size_t *sz)
{

	return(ksql_readbuf(p, sz, sizeof(size_t), 0));
}

/*
 * Read a scalar code "c" from the connection in "p".
 * See ksql_readbuf().
 */
static enum ksqlc
ksql_readcode(struct ksql *p, enum ksqlc *c)
{

	return(ksql_readbuf(p, c, sizeof(enum ksqlc), 0));
}

static enum ksqlc
ksql_readptr(struct ksql *p, struct ksqlstmt **cp)
{

	return(ksql_readbuf(p, cp, sizeof(struct ksqlstmt *), 0));
}

/*
 * Read a nil-terminated string "str" from "fd".
 * The pointer in "buf" must be free()d on success (on failure it will
 * be freed automatically).
 * See ksql_readbuf().
 */
static enum ksqlc
ksql_readstr(struct ksql *p, char **buf)
{
	size_t	 	sz;
	enum ksqlc	c;

	if (KSQL_OK != (c = ksql_readbuf(p, &sz, sizeof(size_t), 0)))
		return(c);
	if (NULL == (*buf = malloc(sz + 1)))
		return(ksql_err(p, KSQL_MEM, strerror(ENOMEM)));
	if (KSQL_OK != (c = ksql_readbuf(p, *buf, sz, 0))) {
		free(*buf);
		return(c);
	}

	(*buf)[sz] = '\0';
	return(KSQL_OK);
}

/*
 * Write buffer "buf" of size "sz" to the daemon connection, which is
 * assumed to have a non-blocking descriptor.
 * (The daemon connection must be valid.)
 * On success (all "sz" bytes written), return KSQL_OK.
 * Otherwise, invoke ksql_err() with the given error code.
 */
static enum ksqlc
ksql_writebuf(struct ksql *p, const void *buf, size_t sz)
{
	size_t	 	 wsz = 0;
	ssize_t	 	 ssz;
	struct pollfd	 pfd;
	int		 rc;
	const char	*msg;

	assert(NULL != p->daemon);
	assert(-1 != p->daemon->fd);

	memset(&pfd, 0, sizeof(struct pollfd));

	pfd.fd = p->daemon->fd;
	pfd.events = POLLOUT;

	while (wsz < sz) {
		/* First poll on output. */
		if ((rc = poll(&pfd, 1, INFTIM)) < 0) {
			msg = strerror(errno);
			return(ksql_err(p, KSQL_SYSTEM, msg));
		} else if (0 == rc) {
			/* This shouldn't happen. */
			msg = "poll writer timeout!?";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		}

		if (POLLOUT & pfd.revents) {
			ssz = write(pfd.fd, buf + wsz, sz - wsz);
			if (ssz < 0) {
				msg = strerror(errno);
				return(ksql_err(p, KSQL_SYSTEM, msg));
			}
			wsz += (size_t)ssz;
		}

		/* Errors in poll? */

		if (POLLHUP & pfd.revents) {
			msg = "poll hup";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		} else if (POLLERR & pfd.revents) {
			msg = "poll error";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		}
	}

	return(KSQL_OK);
}

/*
 * Write a nil-terminated string "str" to the connected process in "p".
 * See ksql_writebuf().
 */
static enum ksqlc
ksql_writestr(struct ksql *p, const char *str)
{
	enum ksqlc	 c;
	size_t		 sz = strlen(str);

	if (KSQL_OK != (c = ksql_writebuf(p, &sz, sizeof(size_t))))
		return(c);
	return(ksql_writebuf(p, str, sz));
}

/*
 * Write a scalar operation "op" to the connected process in "p".
 * See ksql_writebuf().
 */
static enum ksqlc
ksql_writeop(struct ksql *p, enum ksqlop op)
{

	return(ksql_writebuf(p, &op, sizeof(enum ksqlop)));
}

/*
 * Write an opaque pointer "ptr" to the connected process in "p".
 * See ksql_writebuf().
 */
static enum ksqlc
ksql_writeptr(struct ksql *p, const struct ksqlstmt *ptr)
{

	return(ksql_writebuf(p, &ptr, sizeof(struct ksqlstmt *)));
}

/*
 * Write a scalar position "pos" to the connectect process in "p".
 * See ksql_writebuf().
 */
static enum ksqlc
ksql_writepos(struct ksql *p, size_t pos)
{

	return(ksql_writebuf(p, &pos, sizeof(size_t)));
}

/*
 * Write a scalar code "c" to the connected process in "p".
 * See ksql_writebuf().
 */
static enum ksqlc
ksql_writecode(struct ksql *p, enum ksqlc c)
{

	return(ksql_writebuf(p, &c, sizeof(enum ksqlc)));
}

/*
 * Write a parameter of type "op" to bind at position "pos".
 * If "op" is KSQLOP_BIND_NULL, the "buf" and "bufsz" are ignored.
 * Returns the response code read from the connected system.
 */
static enum ksqlc
ksql_writebound(struct ksqlstmt *ss, enum ksqlop op, 
	size_t pos, const void *buf, size_t bufsz)
{
	enum ksqlc	c, cc;

	if (KSQL_OK != (c = ksql_writeop(ss->sql, op)))
		return(c);
	if (KSQL_OK != (c = ksql_writeptr(ss->sql, ss->ptr)))
		return(c);
	if (KSQL_OK != (c = ksql_writepos(ss->sql, pos)))
		return(c);
	if (KSQLOP_BIND_ZBLOB == op) {
		c = ksql_writepos(ss->sql, bufsz);
		if (KSQL_OK != c)
			return(c);
	} else if (KSQLOP_BIND_NULL != op) {
		c = ksql_writepos(ss->sql, bufsz);
		if (KSQL_OK != c)
			return(c);
		c = ksql_writebuf(ss->sql, buf, bufsz);
		if (KSQL_OK != c)
			return(c);
	}
	if (KSQL_OK != (c = ksql_readcode(ss->sql, &cc)))
		return(c);
	return(cc);
}

/*
 * Server version of ksql_close().
 * Simply writes the value of ksql_close().
 * Returns whether communication worked.
 */
static enum ksqlc
ksqlsrv_close(struct ksql *p)
{

	warnx(__func__);
	return(ksql_writecode(p, ksql_close(p)));
}

/*
 * Server version of ksql_open().
 * Accepts the filename, runs the open, returns the response.
 * Returns whether communication worked.
 */
static enum ksqlc
ksqlsrv_open(struct ksql *p)
{
	enum ksqlc	 c;
	char		*dbfile;

	if (KSQL_OK != (c = ksql_readstr(p, &dbfile)))
		return(c);

	c = ksql_open(p, dbfile);
	warnx("%s: opened: %s", __func__, dbfile);
	free(dbfile);
	return(ksql_writecode(p, c));
}

static enum ksqlc
ksqlsrv_bind(struct ksql *p, enum ksqlop op)
{
	enum ksqlc	 c;
	size_t		 pos;
	char		*buf = NULL;
	struct ksqlstmt	*ss;
	size_t		 bufsz;

	if (KSQL_OK != (c = ksql_readptr(p, &ss)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &pos)))
		return(c);

	if (KSQLOP_BIND_TEXT == op) {
		if (KSQL_OK != (c = ksql_readstr(p, &buf)))
			return(c);
		c = ksql_bind_str(ss, pos, buf);
	} else if (KSQLOP_BIND_ZBLOB == op) {
		if (KSQL_OK != (c = ksql_readpos(p, &bufsz)))
			return(c);
		c = ksql_bind_zblob(ss, pos, bufsz);
	} else if (KSQLOP_BIND_NULL != op) {
		if (KSQL_OK != (c = ksql_readpos(p, &bufsz)))
			return(c);
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

/*
 * TODO: use a string buffer for "sql".
 */
static enum ksqlc
ksqlsrv_stmt_alloc(struct ksql *p)
{
	struct ksqlstmt	*ss;
	char		*sql = NULL;
	size_t		 id;
	enum ksqlc	 c, cc;

	if (KSQL_OK != (c = ksql_readstr(p, &sql)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &id))) {
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

	warnx("%s: allocated statement: %p", __func__, ss);

	/* We now know that "ss" is non-NULL. */

	assert(NULL != ss);
	return(ksql_writeptr(p, ss));
}

static enum ksqlc
ksqlsrv_stmt_step(struct ksql *p)
{
	size_t		 val;
	struct ksqlstmt	*ss;
	enum ksqlc	 c;

	if (KSQL_OK != (c = ksql_readptr(p, &ss)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &val)))
		return(c);
	return(ksql_writecode(p, ksql_step_inner(ss, val)));
}


static enum ksqlc
ksqlsrv_stmt_reset(struct ksql *p)
{
	struct ksqlstmt	*ss;
	enum ksqlc	 c;

	if (KSQL_OK != (c = ksql_readptr(p, &ss)))
		return(c);
	return(ksql_stmt_reset(ss));
}

static enum ksqlc
ksqlsrv_stmt_free(struct ksql *p)
{
	struct ksqlstmt	*ss;
	enum ksqlc	 c;

	if (KSQL_OK != (c = ksql_readptr(p, &ss)))
		return(c);

	warnx("%s: %p", __func__, ss);

	/* Return code form ksql_stmt_free always KSQL_OK */

	return(ksql_stmt_free(ss));
}

static enum ksqlc
ksqlsrv_stmt_bytes(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	size_t		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &col)))
		return(c);
	val = ksql_stmt_double(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(size_t)));
}

static enum ksqlc
ksqlsrv_stmt_double(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	double		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &col)))
		return(c);
	val = ksql_stmt_double(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(double)));
}

static enum ksqlc
ksqlsrv_stmt_isnull(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	int		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &col)))
		return(c);
	val = ksql_stmt_isnull(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(int)));
}


static enum ksqlc
ksqlsrv_stmt_int(struct ksql *p)
{
	enum ksqlc	 c;
	struct ksqlstmt	*stmt;
	size_t		 col;
	int64_t		 val;

	if (KSQL_OK != (c = ksql_readptr(p, &stmt)))
		return(c);
	if (KSQL_OK != (c = ksql_readpos(p, &col)))
		return(c);
	val = ksql_stmt_int(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(int64_t)));
}

struct ksql *
ksql_alloc_secure(const struct ksqlcfg *cfg,
	void (*cb)(void *), void *arg)
{
	struct ksql	*p;
	struct ksqld	*d;
	int		 fd[2], comm;
	enum ksqlop	 op;
	pid_t		 pid;
	enum ksqlc	 c;

	/* Begin by setting up our parent/child with a comm. */

	if (-1 == socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd)) {
		return(NULL);
	} else if (-1 == (pid = fork())) {
		close(fd[0]);
		close(fd[1]);
		return(NULL);
	} else if (pid > 0) {
		/*
		 * We're in the parent.
		 * Create a dummy ksql that will have only an active
		 * ksqld for communicating with the child.
		 */

		warnx("%s: parent", __func__);

		close(fd[1]);
		if (NULL == (p = calloc(1, sizeof(struct ksql))) ||
		    NULL == (d = calloc(1, sizeof(struct ksqld)))) {
			close(fd[0]);
			free(p);
			return(NULL);
		}
		p->daemon = d;
		d->fd = fd[0];
		d->pid = pid;
		return(p);
	}

	warnx("%s: child", __func__);

	/* Close out the other socketpair end. */

	comm = fd[1];
	close(fd[0]);

	/* Invoke our child-cleaning context. */

	if (NULL != cb)
		(*cb)(arg);

	/* Wipe all of our parent context *except* stderr. */

	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	/* Fully allocate the ksql context. */

	if (NULL == (p = ksql_alloc(cfg))) {
		close(comm);
		exit(EXIT_FAILURE);
	}
	p->daemon = calloc(1, sizeof(struct ksqld));
	if (NULL == p->daemon) {
		ksql_free(p);
		exit(EXIT_FAILURE);
	}
	p->daemon->fd = comm;

	warnx("%s: allocated: %p", __func__, p);

	/* Now we loop on operations. */

	c = KSQL_OK;

	while (KSQL_OK == c) {
		if (KSQL_EOF == (c = ksql_readop(p, &op))) {
			warnx("%s: child exiting", __func__);
			break;
		} else if (KSQL_OK != c)
			break;
		warnx("%s: child: %s", __func__, ksqlops[op]);
		switch (op) {
		case (KSQLOP_BIND_DOUBLE):
		case (KSQLOP_BIND_INT):
		case (KSQLOP_BIND_NULL):
			c = ksqlsrv_bind(p, op);
			break;
		case (KSQLOP_CLOSE):
			c = ksqlsrv_close(p);
			break;
		case (KSQLOP_COL_BYTES):
			c = ksqlsrv_stmt_bytes(p);
			break;
		case (KSQLOP_COL_DOUBLE):
			c = ksqlsrv_stmt_double(p);
			break;
		case (KSQLOP_COL_INT):
			c = ksqlsrv_stmt_int(p);
			break;
		case (KSQLOP_COL_ISNULL):
			c = ksqlsrv_stmt_isnull(p);
			break;
		case (KSQLOP_OPEN):
			c = ksqlsrv_open(p);
			break;
		case (KSQLOP_STMT_ALLOC):
			c = ksqlsrv_stmt_alloc(p);
			break;
		case (KSQLOP_STMT_FREE):
			c = ksqlsrv_stmt_free(p);
			break;
		case (KSQLOP_STMT_RESET):
			c = ksqlsrv_stmt_reset(p);
			break;
		case (KSQLOP_STMT_STEP):
			c = ksqlsrv_stmt_step(p);
			break;
		default:
			abort();
		}
	}

	ksql_free(p);
	exit(KSQL_EOF == c ? EXIT_SUCCESS : EXIT_FAILURE);
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
		p->cfg.dberr = ksqlitedbmsg;
		p->cfg.err = ksqlitemsg;
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
	enum ksqlc	 haserrs, c;
	int		 ischild;

	haserrs = KSQL_OK;

	/* Short-circuit. */
	if (NULL == p || NULL == p->db)
		return(KSQL_OK);

	ischild = KSQLSRV_ISCHILD(p);

	if (onexit)
		ksql_err_noexit(p, KSQL_EXIT, NULL);

	/* 
	 * Finalise out all open statements first. 
	 * Don't run ksql_err() yet because it will kill the process
	 * and we want to free these now.
	 */
	while ( ! TAILQ_EMPTY(&p->stmt_used)) {
		stmt = TAILQ_FIRST(&p->stmt_used);
		warnx("%s: closing: %p", __func__, stmt);
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
		snprintf(buf, sizeof(buf),
			"transaction %zu still open", p->trans);
		ksql_err_noexit(p, KSQL_TRANS, buf);
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
	enum ksqlc	 c, cc;

	warnx(__func__);

	if (KSQLSRV_ISPARENT(p)) {
		if (KSQL_OK != (c = ksql_writeop(p, KSQLOP_CLOSE)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	}

	return(ksql_close_inner(p, 0));
}

/*
 * Frees memory.
 * If this is the parent of a parent-child system, then it also closes
 * the file descriptor and waits for exit.
 * This calls through to ksql_close_inner() as well.
 */
static enum ksqlc
ksql_free_inner(struct ksql *p, int onexit)
{
	struct ksqlstmt	*stmt;
	enum ksqlc	 er = KSQL_OK;

	if (NULL == p)
		return(KSQL_OK);

	if (KSQLSRV_ISPARENT(p)) {
		warnx("%s: parent", __func__);
		close(p->daemon->fd);
		waitpid(p->daemon->pid, NULL, 0);
	} else if (KSQLSRV_ISCHILD(p)) {
		warnx("%s: child", __func__);
		er = ksql_close_inner(p, onexit);
		close(p->daemon->fd);
	} else {
		er = ksql_close_inner(p, onexit);
	}

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

	free(p->daemon);
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
	enum ksqlc	 er, cc;

	/* Optionally perform parent->child communication. */

	if (KSQLSRV_ISPARENT(p)) {
		if (KSQL_OK != (er = ksql_writeop(p, KSQLOP_OPEN)))
			return(er);
		if (KSQL_OK != (er = ksql_writestr(p, dbfile)))
			return(er);
		if (KSQL_OK != (er = ksql_readcode(p, &cc)))
			return(er);
		return(cc);
	}

	/* 
	 * Now in-process mode. 
	 * First close out any existing open database. 
	 * (Note that, since we're in the child, this won't incur any
	 * additional communication with the parent, so we're safe to
	 * run it entirely locally).
	 */

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

/*
 * Accommodate for both constraint-step (step where we allow constraint
 * failures not to tank the step) and regular step.
 */
static enum ksqlc
ksql_step_inner(struct ksqlstmt *stmt, size_t cstr)
{
	int	 	rc;
	size_t	 	attempt = 0;
	enum ksqlc	c, cc;

	if (KSQLSRV_ISPARENT(stmt->sql)) {
		c = ksql_writeop(stmt->sql, KSQLOP_STMT_STEP);
		if (KSQL_OK != c)
			return(c);
		c = ksql_writeptr(stmt->sql, stmt->ptr);
		if (KSQL_OK != c)
			return(c);
		c = ksql_writepos(stmt->sql, cstr);
		if (KSQL_OK != c)
			return(c);
		c = ksql_readcode(stmt->sql, &cc);
		if (KSQL_OK != c)
			return(c);
		return(cc);
	}

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

enum ksqlc
ksql_stmt_reset(struct ksqlstmt *stmt)
{
	enum ksqlc	 c;

	if (KSQLSRV_ISPARENT(stmt->sql)) {
		c = ksql_writeop(stmt->sql, KSQLOP_STMT_RESET);
		if (KSQL_OK != c)
			return(c);
		return(ksql_writeptr(stmt->sql, stmt->ptr));
	}

	/* FIXME: error code from reset? */

	sqlite3_reset(stmt->stmt);
	return(KSQL_OK);
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

enum ksqlc
ksql_stmt_free(struct ksqlstmt *stmt)
{
	enum ksqlc	 c;

	if (NULL == stmt)
		return(KSQL_OK);

	if (KSQLSRV_ISPARENT(stmt->sql)) {
		c = ksql_writeop(stmt->sql, KSQLOP_STMT_FREE);
		if (KSQL_OK != c) {
			free(stmt);
			return(c);
		}
		warnx("%s: wrote: %p", __func__, stmt->ptr);
		c = ksql_writeptr(stmt->sql, stmt->ptr);
		free(stmt);
		return(c);
	}

	/* FIXME: error code from finalise? */

	warnx("%s: finalising: %p", __func__, stmt);

	sqlite3_finalize(stmt->stmt);
	stmt->stmt = NULL;
	TAILQ_REMOVE(&stmt->sql->stmt_used, stmt, entries);
	TAILQ_INSERT_TAIL(&stmt->sql->stmt_free, stmt, entries);
	return(KSQL_OK);
}

enum ksqlc
ksql_stmt_alloc(struct ksql *p, 
	struct ksqlstmt **stmt, const char *sql, size_t id)
{
	struct ksqlstmt	*ss;
	size_t		 attempt = 0;
	sqlite3_stmt 	*st;
	int		 rc;
	enum ksqlc	 c, cc;

	*stmt = NULL;

	/* Parent writes arguments, receives code & pointer. */

	if (KSQLSRV_ISPARENT(p)) {
		if (KSQL_OK != (c = ksql_writeop(p, KSQLOP_STMT_ALLOC)))
			return(c);
		if (KSQL_OK != (c = ksql_writestr(p, sql)))
			return(c);
		if (KSQL_OK != (c = ksql_writepos(p, id)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		if (KSQL_OK != cc)
			return(cc);
		if (KSQL_OK != (c = ksql_readptr(p, &ss)))
			return(c);
		assert(NULL != ss);
		*stmt = calloc(1, sizeof(struct ksqlstmt));
		(*stmt)->sql = p;
		(*stmt)->ptr = ss;
		warnx("%s: %p", __func__, ss);
		return(cc);
	}

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
	} else if (SQLITE_OK != rc)
		return(ksql_dberr(p));

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

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_ZBLOB, pos, NULL, valsz));
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

	if (KSQLSRV_ISPARENT(stmt->sql))
		return(ksql_writebound(stmt, 
			KSQLOP_BIND_TEXT, pos, val, strlen(val)));
	rc = sqlite3_bind_text(stmt->stmt, 
		pos + 1, val, -1, SQLITE_STATIC);
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
	if (SQLITE_OK == sqlite3_bind_int64(stmt->stmt, pos + 1, val))
		return(KSQL_OK);
	return(ksql_dberr(stmt->sql));
}

static enum ksqlc
ksql_trans_close_inner(struct ksql *p, int rollback, size_t id)
{
	enum ksqlc	 c;
	char	 	 buf[1024];

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));

	if ( ! (KSQLFL_TRANS & p->flags)) {
		snprintf(buf, sizeof(buf),
			"transaction %zu not open", id);
		return(ksql_err(p, KSQL_TRANS, buf));
	} else if (id != p->trans) {
		snprintf(buf, sizeof(buf),
			"transaction %zu pending on close of %zu", 
			p->trans, id);
		return(ksql_err(p, KSQL_TRANS, buf));
	}

	c = rollback ?
		ksql_exec(p, "ROLLBACK TRANSACTION", SIZE_MAX) :
		ksql_exec(p, "COMMIT TRANSACTION", SIZE_MAX);

	/* Set this only if the exec succeeded.*/
	if (KSQL_OK == c)
		p->flags &= ~KSQLFL_TRANS;

	return(c);
}

static enum ksqlc
ksql_trans_open_inner(struct ksql *p, int immediate, size_t id)
{
	enum ksqlc	 c;
	char		 buf[1024];

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));

	if (KSQLFL_TRANS & p->flags) {
		snprintf(buf, sizeof(buf),
			"transaction %zu still open", p->trans);
		return(ksql_err(p, KSQL_TRANS, buf));
	}

	c = immediate ? 
		ksql_exec(p, "BEGIN IMMEDIATE", SIZE_MAX) : 
		ksql_exec(p, "BEGIN TRANSACTION", SIZE_MAX);

	/* Set this only if the exec succeeded.*/
	if (KSQL_OK == c) {
		p->flags |= KSQLFL_TRANS;
		p->trans = id;
	}
	return(c);
}

enum ksqlc
ksql_trans_open(struct ksql *p, size_t id)
{

	return(ksql_trans_open_inner(p, 0, id));
}

enum ksqlc
ksql_trans_exclopen(struct ksql *p, size_t id)
{

	return(ksql_trans_open_inner(p, 1, id));
}

enum ksqlc
ksql_trans_commit(struct ksql *p, size_t id)
{

	return(ksql_trans_close_inner(p, 0, id));
}

enum ksqlc
ksql_trans_rollback(struct ksql *p, size_t id)
{

	return(ksql_trans_close_inner(p, 1, id));
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

	assert(KSQLSRV_ISCHILD(stmt->sql));

	if (KSQL_OK != ksql_writeop(stmt->sql, op))
		return(0);
	if (KSQL_OK != ksql_writeptr(stmt->sql, stmt->ptr))
		return(0);
	if (KSQL_OK != ksql_writepos(stmt->sql, col))
		return(0);
	if (KSQL_OK != ksql_readbuf(stmt->sql, buf, bufsz, 0))
		return(0);
	return(1);
}

const void *
ksql_stmt_blob(struct ksqlstmt *stmt, size_t col)
{

	return(sqlite3_column_blob(stmt->stmt, (int)col));
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

char *
ksql_stmt_str(struct ksqlstmt *stmt, size_t col)
{

	return((char *)sqlite3_column_text(stmt->stmt, (int)col));
}
