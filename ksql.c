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
 * When obtaining results from the parent-child model, we need to keep
 * track of the pointers in blob and text results to maintain SQLite's
 * invariant that a pointer will be available til the next type
 * conversion, step, reset, or free.
 * This is only applicable for the parent.
 */
struct	kcache {
	void	 		*s; /* pointer to results */
	TAILQ_ENTRY(kcache)	 entries;
};

TAILQ_HEAD(kcacheq, kcache);

/*
 * Holder for pending SQLite statements.
 * If we exit out of state, we'll finalise these statements.
 */
struct	ksqlstmt {
	sqlite3_stmt		*stmt; /* statement */
	size_t			 id; /* its ID (init'd as SIZE_MAX) */
	struct kcacheq		 cache; /* pointer cache */
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
	struct ksqlcfg	 	  cfg;
	size_t			  role; /* current role */
	sqlite3			 *db;
	char			 *dbfile; /* fname of db */
	struct ksqlstmtq	  stmt_used; /* used list */
	struct ksqlstmtq	  stmt_free; /* free list */
	size_t			  trans; /* current transactions */
	struct ksqld		 *daemon; /* if applicable */
	unsigned int		  flags;
#define	KSQLFL_TRANS		  0x01 /* trans is open */
	TAILQ_ENTRY(ksql)	  entries;
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
	"database already open", /* KSQL_ALREADYOPEN */
	"database error", /* KSQL_DB */
	"transaction already open or not yet open", /* KSQL_TRANS */
	"statement(s) open on exit", /* KSQL_STMT */
	"closing on exit", /* KSQL_EXIT */
	"system error", /* KSQL_SYSTEM */
	NULL, /* KSQL_EOF */
	"security violation", /* KSQL_SECURITY */
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
	KSQLOP_COL_BLOB, /* ksql_stmt_blob */
	KSQLOP_COL_BYTES, /* ksql_stmt_bytes */
	KSQLOP_COL_DOUBLE, /* ksql_stmt_double */
	KSQLOP_COL_INT, /* ksql_stmt_int */
	KSQLOP_COL_ISNULL, /* ksql_stmt_isnull */
	KSQLOP_COL_STR, /* ksql_stmt_str */
	KSQLOP_EXEC, /* ksql_exec */
	KSQLOP_LASTID, /* ksql_lastid */
	KSQLOP_OPEN, /* ksql_open */
	KSQLOP_ROLE, /* ksql_role */
	KSQLOP_STMT_ALLOC, /* ksql_stmt_alloc */
	KSQLOP_STMT_FREE, /* ksql_stmt_free */
	KSQLOP_STMT_RESET, /* ksql_stmt_reset */
	KSQLOP_STMT_STEP, /* ksql_stmt_step */
	KSQLOP_TRACE, /* ksql_trace */
	KSQLOP_TRANS_CLOSE, /* ksql_trans_xxxx */
	KSQLOP_TRANS_OPEN, /* ksql_trans_xxxx */
	KSQLOP_UNTRACE, /* ksql_untrace */
};

/*
 * Forward declarations.
 */
static enum ksqlc ksql_free_inner(struct ksql *, int);
static enum ksqlc ksql_step_inner(struct ksqlstmt *, size_t);
static enum ksqlc ksql_trans_open_inner(struct ksql *, size_t, size_t);
static enum ksqlc ksql_trans_close_inner(struct ksql *, size_t, size_t);

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

	while (NULL != (p = TAILQ_FIRST(&ksqls))) {
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
static void
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

	if (0 == sz)
		return(KSQL_OK);

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

		if (POLLERR & pfd.revents) {
			msg = "poll error";
			return(ksql_err(p, KSQL_SYSTEM, msg));
		} 

		if ((POLLIN & pfd.revents) ||
		    (POLLHUP & pfd.revents)) {
			ssz = read(pfd.fd, buf + rsz, sz - rsz);
			if (ssz < 0) {
				msg = strerror(errno);
				return(ksql_err(p, KSQL_SYSTEM, msg));
			} else if (ssz > 0) {
				rsz += (size_t)ssz;
				continue;
			}
			if (eofok && 0 == rsz)
				return(KSQL_EOF);
			msg = "poll hup with pending data";
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
ksql_readsz(struct ksql *p, size_t *sz)
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

	if (0 == sz)
		return(KSQL_OK);

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
ksql_writesz(struct ksql *p, size_t pos)
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
	if (KSQL_OK != (c = ksql_writesz(ss->sql, pos)))
		return(c);
	if (KSQLOP_BIND_TEXT == op) {
		/* Ignore bufsz. */
		c = ksql_writestr(ss->sql, buf);
		if (KSQL_OK != c)
			return(c);
	} else if (KSQLOP_BIND_ZBLOB == op) {
		c = ksql_writesz(ss->sql, bufsz);
		if (KSQL_OK != c)
			return(c);
	} else if (KSQLOP_BIND_NULL != op) {
		/* FIXME: handle zero-length. */
		c = ksql_writesz(ss->sql, bufsz);
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

	return(ksql_writecode(p, ksql_close(p)));
}

static enum ksqlc
ksqlsrv_role(struct ksql *p)
{
	enum ksqlc	 c;
	size_t		 role;

	if (KSQL_OK != (c = ksql_readsz(p, &role)))
		return(c);
	ksql_role(p, role);
	return(ksql_writecode(p, KSQL_OK));
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
	free(dbfile);
	return(ksql_writecode(p, c));
}

static enum ksqlc
ksqlsrv_exec(struct ksql *p)
{
	enum ksqlc	 c, cc;
	size_t		 id;
	char		*sql = NULL;

	if (KSQL_OK != (c = ksql_readstr(p, &sql)))
		return(c);

	if (KSQL_OK != (c = ksql_readsz(p, &id))) {
		free(sql);
		return(c);
	}

	assert(NULL != sql);
	cc = ksql_exec(p, sql, id);
	free(sql);
	return(ksql_writecode(p, cc));
}

static enum ksqlc
ksqlsrv_lastid(struct ksql *p)
{
	enum ksqlc	 c, cc;
	int64_t		 id;

	cc = ksql_lastid(p, &id);
	if (KSQL_OK != (c = ksql_writecode(p, cc)))
		return(c);
	/* Mask local error. */
	if (KSQL_OK != cc)
		return(KSQL_OK);
	return(ksql_writebuf(p, &id, sizeof(int64_t)));
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

static enum ksqlc
ksqlsrv_stmt_step(struct ksql *p)
{
	size_t		 val;
	struct ksqlstmt	*ss;
	enum ksqlc	 c;

	if (KSQL_OK != (c = ksql_readptr(p, &ss)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &val)))
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
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);
	val = ksql_stmt_bytes(stmt, col);
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
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
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
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
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
	if (KSQL_OK != (c = ksql_readsz(p, &col)))
		return(c);
	val = ksql_stmt_int(stmt, col);
	return(ksql_writebuf(p, &val, sizeof(int64_t)));
}

static enum ksqlc
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

static enum ksqlc
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

static enum ksqlc
ksqlsrv_trans_close(struct ksql *p)
{
	enum ksqlc	 c, cc;
	size_t		 type, id;

	if (KSQL_OK != (c = ksql_readsz(p, &type)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &id)))
		return(c);
	cc = ksql_trans_close_inner(p, type, id);
	return(ksql_writecode(p, cc));
}

static enum ksqlc
ksqlsrv_trans_open(struct ksql *p)
{
	enum ksqlc	 c, cc;
	size_t		 type, id;

	if (KSQL_OK != (c = ksql_readsz(p, &type)))
		return(c);
	if (KSQL_OK != (c = ksql_readsz(p, &id)))
		return(c);
	cc = ksql_trans_open_inner(p, type, id);
	return(ksql_writecode(p, cc));
}

struct ksql *
ksql_alloc_child(const struct ksqlcfg *cfg,
	void (*cb)(void *), void *arg)
{
	struct ksql	*p;
	struct ksqld	*d;
	int		 fd[2], comm;
	enum ksqlop	 op;
	pid_t		 pid;
	enum ksqlc	 c;
	int		 flags = SOCK_STREAM;

#if HAVE_SOCK_NONBLOCK
	flags |= SOCK_NONBLOCK;
#endif

	/* Begin by setting up our parent/child with a comm. */

	if (-1 == socketpair(AF_UNIX, flags, 0, fd))
		return(NULL);

#if ! HAVE_SOCK_NONBLOCK
	if (-1 == fcntl(fd[0], F_SETFL, 
	    fcntl(fd[0], F_GETFL, 0) | O_NONBLOCK)) {
		close(fd[0]);
		close(fd[1]);
		return(NULL);
	}
	if (-1 == fcntl(fd[1], F_SETFL, 
	    fcntl(fd[1], F_GETFL, 0) | O_NONBLOCK)) {
		close(fd[0]);
		close(fd[1]);
		return(NULL);
	}
#endif

	if (-1 == (pid = fork())) {
		close(fd[0]);
		close(fd[1]);
		return(NULL);
	} else if (pid > 0) {
		/*
		 * We're in the parent.
		 * Create a dummy ksql that will have only an active
		 * ksqld for communicating with the child.
		 */
		close(fd[1]);
		if (NULL == (p = ksql_alloc(cfg)) ||
		    NULL == (d = calloc(1, sizeof(struct ksqld)))) {
			close(fd[0]);
			free(p);
			/* FIXME: waitpid on child? */
			return(NULL);
		}
		p->daemon = d;
		d->fd = fd[0];
		d->pid = pid;
		return(p);
	}

	/* Close out the other socketpair end. */

	comm = fd[1];
	close(fd[0]);

	/* Invoke our child-cleaning context. */

	if (NULL != cb)
		(*cb)(arg);

#if HAVE_PLEDGE
	if (-1 == pledge("stdio rpath cpath wpath flock fattr", NULL)) {
		close(comm);
		exit(EXIT_FAILURE);
	}
#endif

	/*
	 * We don't want the child to be connected to stdout or stdin
	 * for security reasons.
	 * Make sure they're not connected to a useful channel.
	 */

	if (-1 == dup2(STDERR_FILENO, STDIN_FILENO) ||
	    -1 == dup2(STDERR_FILENO, STDOUT_FILENO)) {
		close(comm);
		exit(EXIT_FAILURE);
	}

	/* Fully allocate the ksql context. */

	if (NULL == (p = ksql_alloc(cfg))) {
		close(comm);
		exit(EXIT_FAILURE);
	}
	p->daemon = calloc(1, sizeof(struct ksqld));
	if (NULL == p->daemon) {
		close(comm);
		ksql_free(p);
		exit(EXIT_FAILURE);
	}
	p->daemon->fd = comm;

	/* Now we loop on operations. */

	c = KSQL_OK;

	while (KSQL_OK == c) {
		if (KSQL_EOF == (c = ksql_readop(p, &op)))
			break;
		else if (KSQL_OK != c)
			break;
		switch (op) {
		case (KSQLOP_BIND_ZBLOB):
		case (KSQLOP_BIND_BLOB):
		case (KSQLOP_BIND_TEXT):
		case (KSQLOP_BIND_DOUBLE):
		case (KSQLOP_BIND_INT):
		case (KSQLOP_BIND_NULL):
			c = ksqlsrv_bind(p, op);
			break;
		case (KSQLOP_CLOSE):
			c = ksqlsrv_close(p);
			break;
		case (KSQLOP_COL_BLOB):
			c = ksqlsrv_stmt_blob(p);
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
		case (KSQLOP_COL_STR):
			c = ksqlsrv_stmt_str(p);
			break;
		case (KSQLOP_EXEC):
			c = ksqlsrv_exec(p);
			break;
		case (KSQLOP_LASTID):
			c = ksqlsrv_lastid(p);
			break;
		case (KSQLOP_OPEN):
			c = ksqlsrv_open(p);
			break;
		case (KSQLOP_ROLE):
			c = ksqlsrv_role(p);
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
		case (KSQLOP_TRACE):
			ksql_trace(p);
			break;
		case (KSQLOP_TRANS_CLOSE):
			c = ksqlsrv_trans_close(p);
			break;
		case (KSQLOP_TRANS_OPEN):
			c = ksqlsrv_trans_open(p);
			break;
		case (KSQLOP_UNTRACE):
			ksql_untrace(p);
			break;
		default:
			abort();
		}
	}

	ksql_free(p);
	exit(KSQL_EOF == c ? EXIT_SUCCESS : EXIT_FAILURE);
}

void
ksql_cfg_defaults(struct ksqlcfg *cfg)
{
	/*
	 * Make some safe defaults here.
	 * Specifically, log all of our database and `soft'
	 * errors to stderr and make us bail on exit, as well
	 * trying to catch signals/exits.
	 */

	memset(cfg, 0, sizeof(struct ksqlcfg));
	cfg->dberr = ksqlitedbmsg;
	cfg->err = ksqlitemsg;
	cfg->flags = KSQL_EXIT_ON_ERR | KSQL_SAFE_EXIT;
}

struct ksql *
ksql_alloc(const struct ksqlcfg *cfg)
{
	struct ksql	*p;

	p = calloc(1, sizeof(struct ksql));
	if (NULL == p)
		return(NULL);

	if (NULL == cfg)
		ksql_cfg_defaults(&p->cfg);
	else
		p->cfg = *cfg;

	/* 
	 * Start in default role.
	 * Has no practical effect if roles are disabled.
	 */

	p->role = p->cfg.roles.defrole;

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
			if (-1 == atexit(ksql_atexit))
				goto err;
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

#if HAVE_ARC4RANDOM
	srandom(arc4random());
#else
	srandom(getpid());
#endif

	TAILQ_INIT(&p->stmt_used);
	TAILQ_INIT(&p->stmt_free);
	return(p);
err:
	free(p);
	return(NULL);

}

static enum ksqlc 
ksql_close_inner(struct ksql *p, int onexit)
{
	struct ksqlstmt	*stmt;
	char		 buf[128];
	enum ksqlc	 haserrs = KSQL_OK, c;

	if (NULL == p)
		return(KSQL_OK);

	/* 
	 * This might be called as the child process.
	 * It's either that or single-process mode.
	 * This is *never* called for the parent in split-process mode.
	 */

	if (onexit)
		ksql_err_noexit(p, KSQL_EXIT, NULL);

	/* 
	 * Finalise out all open statements first. 
	 * Don't run ksql_err() yet because it will kill the process
	 * and we want to free these now.
	 * Only do this as the child process---we'll ignore the fact
	 * that we have open data in the parent and just release it.
	 * (The child will report its errors.)
	 */

	while (NULL != (stmt = TAILQ_FIRST(&p->stmt_used))) {
		TAILQ_REMOVE(&p->stmt_used, stmt, entries);
		if (NULL != stmt->stmt) {
			sqlite3_finalize(stmt->stmt);
			stmt->stmt = NULL;
		}
		snprintf(buf, sizeof(buf),
			"statement %zu still open", stmt->id);
		stmt->id = SIZE_MAX;
		haserrs = KSQL_STMT;
		ksql_err_noexit(p, KSQL_STMT, buf);
		TAILQ_INSERT_TAIL(&p->stmt_free, stmt, entries);
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

	if (NULL != p->db && SQLITE_OK != sqlite3_close(p->db)) {
		/* 
		 * It's unclear whether p->db points to any useful
		 * memory in the case of error.
		 * Assume that it doesn't.
		 */
		ksql_err_noexit(p, KSQL_DB, NULL);
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
		close(p->daemon->fd);
		waitpid(p->daemon->pid, NULL, 0);
		er = ksql_close_inner(p, onexit);
	} else if (KSQLSRV_ISCHILD(p)) {
		er = ksql_close_inner(p, onexit);
		close(p->daemon->fd);
	} else
		er = ksql_close_inner(p, onexit);

	while (NULL != (stmt = TAILQ_FIRST(&p->stmt_free))) {
		TAILQ_REMOVE(&p->stmt_free, stmt, entries);
		assert(NULL == stmt->stmt);
		free(stmt);
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

/*
 * Execute a statement directly without any checks.
 * This is used for child-internal processing (like opening
 * transactions) and as the eventual target for ksql_exec() in the child
 * process, or the caller of a non-split-process.
 */
static enum ksqlc
ksql_exec_private(struct ksql *p, const char *sql)
{
	enum ksqlc	 c;

	c = ksql_exec_inner(p, sql);

	if (KSQL_DB == c)
		return(ksql_dberr(p));
	else if (KSQL_OK != c)
		return(ksql_err(p, c, NULL));

	return(c);
}

#if 0
static int 
xauth(void *arg, int type, const char *arg3, const char *arg4, const char *name, const char *view)
{

	warnx("%d: %s, %s\n", type, NULL == arg3 ? "(null)" : arg3, NULL == arg4 ? "(null)" : arg4);
	return(SQLITE_OK);
}
#endif

/*
 * The logic here is almost identical to ksql_stmt_alloc().
 * Note that we sometimes call ksql_exec() from within the child process
 * directly (e.g., in ksql_open).
 */
enum ksqlc
ksql_exec(struct ksql *p, const char *sql, size_t id)
{
	enum ksqlc	c, cc;

	if (KSQLSRV_ISPARENT(p)) {
		if (NULL == sql)
			sql = "";
		if (KSQL_OK != (c = ksql_writeop(p, KSQLOP_EXEC)))
			return(c);
		if (KSQL_OK != (c = ksql_writestr(p, sql)))
			return(c);
		if (KSQL_OK != (c = ksql_writesz(p, id)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	}

	/* 
	 * Check if configuration requires stored statements. 
	 * If so, ignore "sql" and prime it to the stored version.
	 */

	if (p->cfg.stmts.stmtsz) {
		if (id >= p->cfg.stmts.stmtsz) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"statement %zu exceeds configured "
				"maximum of %zu", id, 
				p->cfg.stmts.stmtsz);
			abort();
		} else if (NULL == (sql = p->cfg.stmts.stmts[id])) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"statement %zu (of %zu statements) "
				"is null", id, p->cfg.stmts.stmtsz);
			abort();
		}
	}

	/*
	 * If the configuration requires roles AND has stored
	 * statements, then make sure the stored statement is allowed
	 * within our role.
	 */

	if (p->cfg.roles.rolesz) {
		if (id >= p->cfg.stmts.stmtsz) { 
			ksqlitevmsg(p, KSQL_SECURITY, 
				"statement %zu exceeds configured "
				"maximum of %zu", id, 
				p->cfg.stmts.stmtsz);
			abort();
		} else if ( ! p->cfg.roles.roles[p->role].stmts[id]) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"role %zu (of %zu roles) disallowed "
				"statement %zu (of %zu statements)",
				p->role, p->cfg.roles.rolesz, id,
				p->cfg.stmts.stmtsz);
			abort();
		}
	}

	return(ksql_exec_private(p, sql));
}

enum ksqlc
ksql_open(struct ksql *p, const char *dbfile)
{
	size_t		 attempt = 0;
	int		 rc;
	enum ksqlc	 c, cc;

	/* Optionally perform parent->child communication. */

	if (KSQLSRV_ISPARENT(p)) {
		if (KSQL_OK != (c = ksql_writeop(p, KSQLOP_OPEN)))
			return(c);
		if (KSQL_OK != (c = ksql_writestr(p, dbfile)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	}

	/* Role check! */

	if (p->cfg.roles.rolesz &&
	    ! (KSQLROLE_OPEN & p->cfg.roles.roles[p->role].flags)) {
		ksqlitevmsg(p, KSQL_SECURITY, 
			"role %zu (of %zu roles) "
			"cannot open databases",
			p->role, p->cfg.roles.rolesz);
		abort();
	}

	/* 
	 * Now in-process mode. 
	 * If we already have a database, don't re-open.
	 */

	if (NULL != p->db) 
		return(KSQL_ALREADYOPEN);

	if (NULL == (p->dbfile = strdup(dbfile)))
		return(ksql_err(p, KSQL_MEM, NULL));
again:
	rc = sqlite3_open(dbfile, &p->db);

	if (SQLITE_BUSY == rc) {
		sqlite3_close(p->db);
		p->db = NULL;
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_LOCKED == rc) {
		sqlite3_close(p->db);
		p->db = NULL;
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_PROTOCOL == rc) {
		sqlite3_close(p->db);
		p->db = NULL;
		ksql_sleep(attempt++);
		goto again;
	} else if (SQLITE_OK != rc) {
		if (NULL != p->db) {
			/*
			 * This is basically ksql_dberr, but we want to
			 * make sure that the database is closed.
			 */
			ksql_dberr_noexit(p);
			sqlite3_close(p->db);
			p->db = NULL;
			if (KSQL_EXIT_ON_ERR & p->cfg.flags)
				exit(EXIT_FAILURE);
			return(KSQL_DB);
		}
		return(ksql_err(p, SQLITE_NOMEM == rc ?
			KSQL_MEM : KSQL_DB, NULL));
	}

	/* TODO... */
	/* sqlite3_set_authorizer(p->db, xauth, NULL); */

	/* Handle required foreign key invocation. */

	return(KSQL_FOREIGN_KEYS & p->cfg.flags ?
		ksql_exec_private(p, "PRAGMA foreign_keys = ON;") :
		KSQL_OK);
}

static void
ksql_cache_flush(struct ksqlstmt *stmt)
{
	struct kcache	*c;

	while (NULL != (c = TAILQ_FIRST(&stmt->cache))) {
		TAILQ_REMOVE(&stmt->cache, c, entries);
		free(c->s);
		free(c);
	}
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
		ksql_cache_flush(stmt);
		c = ksql_writeop(stmt->sql, KSQLOP_STMT_STEP);
		if (KSQL_OK != c)
			return(c);
		c = ksql_writeptr(stmt->sql, stmt->ptr);
		if (KSQL_OK != c)
			return(c);
		c = ksql_writesz(stmt->sql, cstr);
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
	enum ksqlc	 c = KSQL_OK;

	/*
	 * As defined in the SQLite manual, which we'll do as well, we
	 * want to clear our pointer cache if we have a reset and we're
	 * in the parent of a split process.
	 */

	if (KSQLSRV_ISPARENT(stmt->sql)) {
		ksql_cache_flush(stmt);
		c = ksql_writeop(stmt->sql, KSQLOP_STMT_RESET);
		if (KSQL_OK != c)
			return(c);
		c = ksql_writeptr(stmt->sql, stmt->ptr);
	} else
		sqlite3_reset(stmt->stmt);

	/*
	 * XXX: DO NOT RETURN THE CODE OF SQLITE3_RESET.
	 * It will just return the last sqlite3_step, which may have
	 * been a constraint failure, which means this erroneously
	 * returns an error.
	 */

	return(c);
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
	enum ksqlc	 c = KSQL_OK;

	if (NULL == stmt)
		return(KSQL_OK);

	/*
	 * If we're in the parent of a split-process, flush out our
	 * cache of active blob and string pointers and nullify the
	 * underlying statement pointer.
	 * If we're in the child (or in the single process), finalise
	 * the statement.
	 * Then recycle the statement object for both.
	 */

	if (KSQLSRV_ISPARENT(stmt->sql)) {
		ksql_cache_flush(stmt);
		c = ksql_writeop(stmt->sql, KSQLOP_STMT_FREE);
		if (KSQL_OK == c)
			c = ksql_writeptr(stmt->sql, stmt->ptr);
		stmt->ptr = NULL;
	} else {
		/*
		 * XXX: DO NOT RETURN THE CODE OF SQLITE3_FINALIZE.
		 * It will just return the last sqlite3_step, which may
		 * have been a constraint failure, which means this
		 * erroneously returns an error.
		 */
		assert(TAILQ_EMPTY(&stmt->cache));
		sqlite3_finalize(stmt->stmt);
		stmt->stmt = NULL;
	}

	stmt->id = SIZE_MAX;
	TAILQ_REMOVE(&stmt->sql->stmt_used, stmt, entries);
	TAILQ_INSERT_TAIL(&stmt->sql->stmt_free, stmt, entries);
	return(c);
}

void
ksql_role(struct ksql *p, size_t role)
{
	enum ksqlc	 c, cc;
	unsigned int	 flags;
	ksqlmsg		 errmsg;

	/* 
	 * Here, we override some default behaviour.
	 * First, we stipulate that we'll always fail on write errors to
	 * the child.
	 * This protects us from not checking the error code and not
	 * having changed roles.
	 * Second, we make sure our error message logger isn't set.
	 * This protects us from having the caller do funny things when
	 * the error handler is invoked.
	 */

	if (KSQLSRV_ISPARENT(p)) {
		flags = p->cfg.flags;
		errmsg = p->cfg.err;

		p->cfg.flags |= KSQL_EXIT_ON_ERR;
		p->cfg.err = NULL;

		c = ksql_writeop(p, KSQLOP_ROLE);
		assert(KSQL_OK == c);
		c = ksql_writesz(p, role);
		assert(KSQL_OK == c);
		c = ksql_readcode(p, &cc);
		assert(KSQL_OK == c);
		assert(KSQL_OK == cc);

		p->cfg.flags = flags;
		p->cfg.err = errmsg;
		return;
	}

	/* 
	 * Require roles to be enabled.
	 * Now make sure that the requested role "role" may be accessed
	 * from the current role "p->role".
	 */

	if (role >= p->cfg.roles.rolesz) {
		ksqlitevmsg(p, KSQL_SECURITY, 
			"role %zu exceeds configured maximum of "
			"%zu", role, p->cfg.roles.rolesz);
		abort();
	} else if ( ! p->cfg.roles.roles[p->role].roles[role]) {
		ksqlitevmsg(p, KSQL_SECURITY, 
			"role %zu (of %zu roles) disallowed "
			"transition to %zu",
			p->role, p->cfg.roles.rolesz, role);
		abort();
	}

	p->role = role;
}

enum ksqlc
ksql_stmt_alloc(struct ksql *p, 
	struct ksqlstmt **stmt, const char *sql, size_t id)
{
	struct ksqlstmt	*ss, *sp;
	size_t		 attempt = 0;
	sqlite3_stmt 	*st;
	int		 rc;
	enum ksqlc	 c, cc;

	*stmt = NULL;

	/*
	 * If we don't have any spare statements to draw from, allocate
	 * one now before investing in the statement preparation.
	 * Put it on the free list: we'll pull from this imminently.
	 */

	if (TAILQ_EMPTY(&p->stmt_free)) {
		ss = calloc(1, sizeof(struct ksqlstmt));
		if (NULL == ss)
			return(ksql_err(p, KSQL_MEM, NULL));
		TAILQ_INIT(&ss->cache);
		ss->id = SIZE_MAX;
		TAILQ_INSERT_TAIL(&p->stmt_free, ss, entries);
	} 

	/* 
	 * If in a split process, the parent writes arguments, receives
	 * code & pointer.
	 * We only allocate from the free list if we have an active
	 * connetion from the child process ("sp").
	 */

	if (KSQLSRV_ISPARENT(p)) {
		if (NULL == sql)
			sql = "";
		c = ksql_writeop(p, KSQLOP_STMT_ALLOC);
		if (KSQL_OK != c)
			return(c);
		if (KSQL_OK != (c = ksql_writestr(p, sql)))
			return(c);
		if (KSQL_OK != (c = ksql_writesz(p, id)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		if (KSQL_OK != cc)
			return(cc);
		if (KSQL_OK != (c = ksql_readptr(p, &sp)))
			return(c);

		ss = TAILQ_FIRST(&p->stmt_free);
		assert(NULL != ss);
		ss->stmt = NULL;
		ss->sql = p;
		ss->id = id;
		ss->ptr = sp;
		TAILQ_INIT(&ss->cache);
		TAILQ_REMOVE(&p->stmt_free, ss, entries);
		TAILQ_INSERT_TAIL(&p->stmt_used, ss, entries);
		*stmt = ss;
		return(cc);
	}

	/* 
	 * Check if configuration requires stored statements. 
	 * If so, ignore "sql" and prime it to the stored version.
	 */

	if (p->cfg.stmts.stmtsz) {
		if (id >= p->cfg.stmts.stmtsz) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"statement %zu exceeds configured "
				"maximum of %zu", id, 
				p->cfg.stmts.stmtsz);
			abort();
		} else if (NULL == (sql = p->cfg.stmts.stmts[id])) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"undefined statement %zu "
				"(of %zu statements)",
				id, p->cfg.stmts.stmtsz);
			abort();
		}
	}

	/*
	 * Do we have roles enabled?
	 * If so, make sure that we're allowed this operation.
	 */

	if (p->cfg.roles.rolesz) {
		if (id >= p->cfg.stmts.stmtsz) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"statement %zu exceeds configured "
				"maximum of %zu", id, 
				p->cfg.stmts.stmtsz);
			abort();
		} else if ( ! p->cfg.roles.roles[p->role].stmts[id]) {
			ksqlitevmsg(p, KSQL_SECURITY, 
				"role %zu (of %zu roles) disallowed "
				"statement %zu (of %zu statements)",
				p->role, p->cfg.roles.rolesz, id,
				p->cfg.stmts.stmtsz);
			abort();
		}
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
	ss->ptr = NULL;
	TAILQ_INIT(&ss->cache);
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
ksql_trans_close_inner(struct ksql *p, size_t mode, size_t id)
{
	enum ksqlc	 c, cc;
	char	 	 buf[1024];

	if (KSQLSRV_ISPARENT(p)) {
		c = ksql_writeop(p, KSQLOP_TRANS_CLOSE);
		if (KSQL_OK != c)
			return(c);
		if (KSQL_OK != (c = ksql_writesz(p, mode))) 
			return(c);
		if (KSQL_OK != (c = ksql_writesz(p, id)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	}

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

	c = mode ?
		ksql_exec_private(p, "ROLLBACK TRANSACTION") :
		ksql_exec_private(p, "COMMIT TRANSACTION");

	/* Set this only if the exec succeeded.*/

	if (KSQL_OK == c)
		p->flags &= ~KSQLFL_TRANS;

	return(c);
}

static enum ksqlc
ksql_trans_open_inner(struct ksql *p, size_t mode, size_t id)
{
	enum ksqlc	 c, cc;
	char		 buf[1024];

	if (KSQLSRV_ISPARENT(p)) {
		c = ksql_writeop(p, KSQLOP_TRANS_OPEN);
		if (KSQL_OK != c)
			return(c);
		if (KSQL_OK != (c = ksql_writesz(p, mode))) 
			return(c);
		if (KSQL_OK != (c = ksql_writesz(p, id)))
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	}

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));

	if (KSQLFL_TRANS & p->flags) {
		snprintf(buf, sizeof(buf),
			"transaction %zu still open", p->trans);
		return(ksql_err(p, KSQL_TRANS, buf));
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

	return(ksql_trans_open_inner(p, 2, id));
}

enum ksqlc
ksql_trans_singleopen(struct ksql *p, size_t id)
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
	enum ksqlc	c, cc;
	int64_t		buf;

	/* 
	 * If we're not given an identifier pointer (why!?), then fake
	 * one up so we can return consistent error messages.
	 */

	if (NULL == id)
		id = &buf;

	if (KSQLSRV_ISPARENT(p)) {
		if (KSQL_OK != (c = ksql_writeop(p, KSQLOP_LASTID))) 
			return(c);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		if (KSQL_OK != cc)
			return(cc);
		return(ksql_readbuf(p, id, sizeof(int64_t), 0));
	}

	if (NULL == p->db) 
		return(ksql_err(p, KSQL_NOTOPEN, NULL));
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

enum ksqlc
ksql_trace(struct ksql *p)
{
	enum ksqlc	 c, cc;
	int		 rc;

	if (KSQLSRV_ISPARENT(p)) {
		ksql_writeop(p, KSQLOP_TRACE);
		if (KSQL_OK != (c = ksql_readcode(p, &cc)))
			return(c);
		return(cc);
	} 

	rc = sqlite3_config
		(SQLITE_CONFIG_LOG, ksql_tracemsg, p);

	if (SQLITE_MISUSE == rc)
		cc = KSQL_ALREADYOPEN;
	else if (SQLITE_OK != rc)
		cc = KSQL_SYSTEM;
	else
		cc = KSQL_OK;

	return(ksql_writecode(p, cc));
}

void
ksql_untrace(struct ksql *p)
{

	if (KSQLSRV_ISPARENT(p))
		ksql_writeop(p, KSQLOP_UNTRACE);
	else
		sqlite3_config(SQLITE_CONFIG_LOG, NULL, NULL);
}


