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
};

typedef	void (*ksqldbmsg)(void *, int, int, const char *, const char *);
typedef	void (*ksqlmsg)(void *, enum ksqlc, const char *);

struct	ksqlcfg {
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
enum ksqlc	 ksql_bind_blob(struct ksqlstmt *, 
			size_t, const void *, size_t);
enum ksqlc	 ksql_bind_double(struct ksqlstmt *, size_t, double);
enum ksqlc	 ksql_bind_int(struct ksqlstmt *, size_t, int64_t);
enum ksqlc	 ksql_bind_null(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_bind_str(struct ksqlstmt *, size_t, const char *);
enum ksqlc	 ksql_bind_zblob(struct ksqlstmt *, size_t, size_t);
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
void		 ksql_stmt_free(struct ksqlstmt *);
int64_t		 ksql_stmt_int(struct ksqlstmt *, size_t);
void		 ksql_stmt_reset(struct ksqlstmt *);
enum ksqlc	 ksql_stmt_step(struct ksqlstmt *);
char		*ksql_stmt_str(struct ksqlstmt *, size_t);
enum ksqlc	 ksql_trans_commit(struct ksql *);
enum ksqlc	 ksql_trans_exclopen(struct ksql *);
enum ksqlc	 ksql_trans_open(struct ksql *);
enum ksqlc	 ksql_trans_rollback(struct ksql *);

__END_DECLS

#endif
