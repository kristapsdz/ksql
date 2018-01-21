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
#ifndef KSQL_H
#define KSQL_H

/*
 * Error codes returned by all functions.
 * In general, checking for zero means success.
 */
enum ksqlc {
	KSQL_OK = 0, /* success */
	KSQL_DONE, /* data done */
	KSQL_ROW, /* row of data */
	KSQL_CONSTRAINT, /* step constraint */
	KSQL_MEM, /* failure to prepare */
	KSQL_NOTOPEN, /* DB not open */
	KSQL_DB, /* errors in DB */
	KSQL_TRANS, /* transaction recursive or not started */
	KSQL_STMT, /* statement still open at close */
	KSQL_EXIT, /* closing database on exit */
	KSQL_SYSTEM, /* system error (fork, socketpair, etc.) */
	KSQL_NOSTORE, /* stored statement not found */
	KSQL_EOF, /* internal only */
};

typedef	void (*ksqldbmsg)(void *, int, int, const char *, const char *);
typedef	void (*ksqlmsg)(void *, enum ksqlc, const char *, const char *);

struct	ksqlstmts {
	const char *const *stmts;
	size_t		  stmtsz;
};

struct	ksqlcfg {
	struct ksqlstmts  stmts;
	unsigned int	  flags;
#define	KSQL_EXIT_ON_ERR  0x01
#define	KSQL_FOREIGN_KEYS 0x02
#define	KSQL_SAFE_EXIT    0x04
	ksqlmsg	 	  err;
	ksqldbmsg	  dberr;
	void		 *arg;
};

struct	ksql;
struct	ksqlstmt;

__BEGIN_DECLS

struct ksql	*ksql_alloc(const struct ksqlcfg *);
struct ksql	*ksql_alloc_child(const struct ksqlcfg *, void(*)(void *), void *);
enum ksqlc	 ksql_bind_blob(struct ksqlstmt *, 
			size_t, const void *, size_t);
enum ksqlc	 ksql_bind_double(struct ksqlstmt *, size_t, double);
enum ksqlc	 ksql_bind_int(struct ksqlstmt *, size_t, int64_t);
enum ksqlc	 ksql_bind_null(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_bind_str(struct ksqlstmt *, size_t, const char *);
enum ksqlc	 ksql_bind_zblob(struct ksqlstmt *, size_t, size_t);
void		 ksql_cfg_defaults(struct ksqlcfg *);
enum ksqlc	 ksql_close(struct ksql *);
enum ksqlc	 ksql_exec(struct ksql *, const char *, size_t);
enum ksqlc	 ksql_free(struct ksql *);
enum ksqlc	 ksql_lastid(struct ksql *, int64_t *);
enum ksqlc	 ksql_open(struct ksql *, const char *);
enum ksqlc	 ksql_stmt_alloc(struct ksql *, 
			struct ksqlstmt **, const char *, size_t);
const void	*ksql_stmt_blob(struct ksqlstmt *, size_t);
size_t		 ksql_stmt_bytes(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_stmt_cstep(struct ksqlstmt *);
double		 ksql_stmt_double(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_stmt_free(struct ksqlstmt *);
int64_t		 ksql_stmt_int(struct ksqlstmt *, size_t);
int		 ksql_stmt_isnull(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_stmt_reset(struct ksqlstmt *);
enum ksqlc	 ksql_stmt_step(struct ksqlstmt *);
const char	*ksql_stmt_str(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_trans_commit(struct ksql *, size_t);
enum ksqlc	 ksql_trans_exclopen(struct ksql *, size_t);
enum ksqlc	 ksql_trans_open(struct ksql *, size_t);
enum ksqlc	 ksql_trans_rollback(struct ksql *, size_t);
enum ksqlc	 ksql_trans_singleopen(struct ksql *, size_t);

void		 ksql_trace(struct ksql *);
void		 ksql_untrace(struct ksql *);

void		 ksqlitedbmsg(void *, int, int, const char *, const char *);
void		 ksqlitemsg(void *, enum ksqlc, const char *, const char *);

__END_DECLS

#endif
