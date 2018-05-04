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
 * Stringification of version major, minor, and build.
 * I have on idea if this is necessary.
 */
#define NAME(s) NAME0(s)
#define NAME0(s) #s
#define NAME2(x,y,z) x ## . ## y ## . ## z
#define NAME1(x,y,z) NAME2(x,y,z)

/*
 * Major version.
 */
#define	KSQL_VMAJOR	0

/*
 * Minor version.
 */
#define	KSQL_VMINOR	3

/*
 * Build version.
 */
#define	KSQL_VBUILD	1

/*
 * Version string of major.minor.build (as a literal string).
 */
#define	KSQL_VERSION	NAME(NAME1(KSQL_VMAJOR,KSQL_VMINOR,KSQL_VBUILD))

/*
 * Integral stamp of version.
 * Guaranteed to be increasing with build, minor, and major.
 * (Assumes build and minor never go over 100.)
 */
#define	KSQL_VSTAMP \
	((KSQL_VBUILD+1) + \
	 (KSQL_VMINOR+1)*100 + \
	 (KSQL_VMAJOR+1)*10000)

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
	KSQL_ALREADYOPEN, /* DB already open */
	KSQL_DB, /* errors in DB */
	KSQL_TRANS, /* transaction recursive or not started */
	KSQL_STMT, /* statement still open at close */
	KSQL_EXIT, /* closing database on exit */
	KSQL_SYSTEM, /* system error (fork, socketpair, etc.) */
	KSQL_EOF, /* internal only */
	KSQL_SECURITY, /* security breach */
	KSQL_BINDCOL, /* invalid bind column index */
	KSQL_RESULTCOL, /* invalid result column index */
	KSQL_NULL, /* NULL value when requesting result */
};

typedef	void (*ksqldbmsg)(void *, int, int, const char *, const char *);
typedef	void (*ksqlmsg)(void *, enum ksqlc, const char *, const char *);

struct	ksqlrole {
	const int	  *roles; /* roles we can access */
	const int	  *stmts; /* statements we can call */
	unsigned int	   flags; /* additional role properties */
#define	KSQLROLE_OPEN	   0x01 /* open new databases */
};

struct	ksqlroles {
	struct ksqlrole	  *roles;
	size_t		   rolesz;
	size_t		   defrole;
};

struct	ksqlstmts {
	const char *const *stmts;
	size_t		   stmtsz;
};

struct	ksqlcfg {
	struct ksqlstmts  stmts;
	struct ksqlroles  roles;
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
enum ksqlc	 ksql_result_blob(struct ksqlstmt *, const void **, size_t *, size_t);
enum ksqlc	 ksql_result_bytes(struct ksqlstmt *, size_t *, size_t);
enum ksqlc	 ksql_result_double(struct ksqlstmt *, double *, size_t);
enum ksqlc	 ksql_result_int(struct ksqlstmt *, int64_t *, size_t);
enum ksqlc	 ksql_result_isnull(struct ksqlstmt *, int *, size_t);
enum ksqlc	 ksql_result_str(struct ksqlstmt *, const char **, size_t);
void		 ksql_role(struct ksql *, size_t);
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

enum ksqlc	 ksql_trace(struct ksql *);
enum ksqlc	 ksql_untrace(struct ksql *);

void		 ksqlitedbmsg(void *, int, int, const char *, const char *);
void		 ksqlitemsg(void *, enum ksqlc, const char *, const char *);

__END_DECLS

#endif
