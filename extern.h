/*	$Id$ */
/*
 * Copyright (c) 2018 Kristaps Dzonsons <kristaps@bsd.lv>
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
#ifndef EXTERN_H
#define EXTERN_H

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
	KSQLOP_RESULT_INT, /* ksql_result_int */
	KSQLOP_RESULT_STR, /* ksql_result_str */
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

TAILQ_HEAD(kcacheq, kcache);
TAILQ_HEAD(ksqlstmtq, ksqlstmt);

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

/*
 * Holder for pending SQLite statements.
 * If we exit out of state, we'll finalise these statements.
 */
struct	ksqlstmt {
	sqlite3_stmt		*stmt; /* statement */
	size_t			 id; /* its ID (init'd as SIZE_MAX) */
	size_t			 bcols; /* valid bind columns */
	size_t			 rcols; /* valid result set columns */
	struct kcacheq		 cache; /* pointer cache */
	struct ksql		*sql; /* corresponding db */
	void			*ptr; /* daemon mode pointer */
	TAILQ_ENTRY(ksqlstmt) 	 entries;
};

#define	KSQLSRV_ISPARENT(_p) \
	(NULL != (_p)->daemon && (_p)->daemon->pid)
#define	KSQLSRV_ISCHILD(_p) \
	(NULL != (_p)->daemon && 0 == (_p)->daemon->pid)

__BEGIN_DECLS

enum ksqlc	 ksql_err(struct ksql *, enum ksqlc, const char *);
void		 ksql_err_noexit(struct ksql *, enum ksqlc, const char *);
enum ksqlc	 ksql_dberr(struct ksql *);
enum ksqlc	 ksql_verr(struct ksql *, enum ksqlc, const char *, ...);

enum ksqlc	 ksql_readbuf(struct ksql *, void *, size_t, int);
enum ksqlc	 ksql_readcode(struct ksql *, enum ksqlc *);
enum ksqlc	 ksql_readptr(struct ksql *, struct ksqlstmt **);
enum ksqlc	 ksql_readstr(struct ksql *, char **);
enum ksqlc	 ksql_readsz(struct ksql *, size_t *);

enum ksqlc	 ksql_writebound(struct ksqlstmt *, enum ksqlop, size_t, const void *, size_t);
enum ksqlc	 ksql_writecode(struct ksql *, enum ksqlc);
enum ksqlc	 ksql_writeop(struct ksql *, enum ksqlop);
enum ksqlc	 ksql_writeptr(struct ksql *, const struct ksqlstmt *);
enum ksqlc	 ksql_writesz(struct ksql *, size_t);

enum ksqlc	 ksqlsrv_bind(struct ksql *, enum ksqlop);
enum ksqlc	 ksqlsrv_stmt_alloc(struct ksql *);


__END_DECLS

#endif
