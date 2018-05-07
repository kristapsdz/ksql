/*	$Id$ */
/*
 * Copyright (c) 2017--2018 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <sys/types.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ksql.h"

static	const size_t insertsz = 50;

static	const char *const stmts[] = {
	"INSERT INTO test (foo,bar,baz,xyzzy) VALUES (?,?,?,?)",
	"SELECT foo,bar,baz,xyzzy,id FROM test",
	"DELETE FROM test",
};

/*
 * This is not a regression test.
 * It's just a playground to test functionality as I develop it.
 */

static void
insert(struct ksql *sql, struct ksqlstmt *stmt, size_t *index, int *nulls)
{
	uint32_t	 val;
	char		 buf[64];
	int64_t		 id;

#if HAVE_ARC4RANDOM
	val = arc4random();
#else
	val = random();
#endif
	snprintf(buf, sizeof(buf), "%" PRIu32, val);

	if (0 == (val % 2)) {
		nulls[*index] = 0;
		if (KSQL_OK != ksql_bind_int(stmt, 0, val))
			errx(EXIT_FAILURE, "ksql_bind_int");
		if (KSQL_OK != ksql_bind_str(stmt, 1, buf))
			errx(EXIT_FAILURE, "ksql_bind_str");
		if (KSQL_OK != ksql_bind_blob
		    (stmt, 2, buf, strlen(buf) + 1))
			errx(EXIT_FAILURE, "ksql_bind_str");
		if (KSQL_OK != ksql_bind_double(stmt, 3, val * 0.5))
			errx(EXIT_FAILURE, "ksql_bind_double");
	} else {
		nulls[*index] = 1;
		if (KSQL_OK != ksql_bind_null(stmt, 0))
			errx(EXIT_FAILURE, "ksql_bind_null");
		if (KSQL_OK != ksql_bind_null(stmt, 1))
			errx(EXIT_FAILURE, "ksql_bind_null");
		if (KSQL_OK != ksql_bind_zblob
		    (stmt, 2, strlen(buf) + 1))
			errx(EXIT_FAILURE, "ksql_bind_str");
		if (KSQL_OK != ksql_bind_null(stmt, 3))
			errx(EXIT_FAILURE, "ksql_bind_null");
	}
	if (KSQL_DONE != ksql_stmt_step(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_step");
	if (KSQL_OK != ksql_lastid(sql, &id))
		errx(EXIT_FAILURE, "ksql_lastid");
	if (KSQL_OK != ksql_stmt_reset(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_reset");

	(*index)++;
}

int
main(void)
{
	struct ksql	*sql;
	struct ksqlcfg	 cfg;
	struct ksqlstmt	*stmt;
	int		 nulls[insertsz * 2], isnull;
	const char	*valstr, *valstr2;
	size_t	 	 i, inserted = 0, valblobsz, valblobsz2;
	const void	*valblob, *valblob2;
	double		 valdouble, valdouble2;
	int64_t		 valint, valint2;
	const int	 stmts0[] = { 1, 1, 0 };
	const int	 stmts1[] = { 1, 1, 0 };
	const int	 stmts2[] = { 1, 1, 0 };
	const int	 stmts3[] = { 0, 0, 1 };
	const int	 roles0[] = { 1, 0, 0, 0 }; /* To noone. */
	const int	 roles1[] = { 1, 1, 0, 0 }; /* Only to root. */
	const int	 roles2[] = { 0, 1, 1, 0 }; /* Only to above. */
	const int	 roles3[] = { 1, 1, 1, 1 }; /* To all. */
	struct ksqlrole	 roles[4] = {
		{ roles0, stmts0, 0 },
		{ roles1, stmts1, 0 },
		{ roles2, stmts2, 0 },
		{ roles3, stmts3, 1 },
	};

#if HAVE_PLEDGE
	if (-1 == pledge("stdio rpath cpath wpath flock fattr proc", NULL))
		err(EXIT_FAILURE, "pledge");
#endif
#if ! HAVE_ARC4RANDOM
	srandom(getpid());
#endif
	memset(&cfg, 0, sizeof(struct ksqlcfg));
	cfg.flags = KSQL_EXIT_ON_ERR | KSQL_SAFE_EXIT;
	cfg.err = ksqlitemsg;
	cfg.dberr = ksqlitedbmsg;
	cfg.stmts.stmts = stmts;
	cfg.stmts.stmtsz = 3;
	cfg.roles.roles = roles;
	cfg.roles.rolesz = 4;
	cfg.roles.defrole = 3;

	if (NULL == (sql = ksql_alloc_child(&cfg, NULL, NULL)))
		errx(EXIT_FAILURE, "ksql_alloc_child");
#if HAVE_PLEDGE
	if (-1 == pledge("stdio", NULL))
		err(EXIT_FAILURE, "pledge");
#endif
	if (KSQL_OK != ksql_open(sql, "test.db"))
		errx(EXIT_FAILURE, "ksql_open");

	if (KSQL_OK != ksql_exec(sql, NULL, 2))
		errx(EXIT_FAILURE, "ksql_exec");

	/* Play around with roles. */

	ksql_role(sql, 2);
	ksql_role(sql, 1);

	/*
	 * Perform a whole bunch of insertions.
	 * Some will be NULL (randomly), others won't.
	 * We record which are which in "nulls".
	 */

	if (KSQL_OK != ksql_trans_open(sql, 0))
		errx(EXIT_FAILURE, "ksql_trans_open");
	if (KSQL_OK != ksql_stmt_alloc(sql, &stmt, NULL, 0))
		errx(EXIT_FAILURE, "ksql_stmt_alloc");
	for (i = 0; i < insertsz; i++) 
		insert(sql, stmt, &inserted, nulls);
	if (KSQL_OK != ksql_stmt_free(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_free");
	if (KSQL_OK != ksql_trans_commit(sql, 0))
		errx(EXIT_FAILURE, "ksql_trans_open");

	/* Now do the same thing, but without a transaction. */

	if (KSQL_OK != ksql_stmt_alloc(sql, &stmt, NULL, 0))
		errx(EXIT_FAILURE, "ksql_stmt_alloc");
	for (i = 0; i < insertsz; i++)
		insert(sql, stmt, &inserted, nulls);
	if (KSQL_OK != ksql_stmt_free(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_free");

	/* Now we're going to get data out. */

	if (KSQL_OK != ksql_stmt_alloc(sql, &stmt, NULL, 1))
		errx(EXIT_FAILURE, "ksql_stmt_alloc");

	i = 0;
	while (KSQL_ROW == ksql_stmt_step(stmt)) {
		valint = ksql_stmt_int(stmt, 0);
		valstr = ksql_stmt_str(stmt, 1);
		valblob = ksql_stmt_blob(stmt, 2);
		valblobsz = ksql_stmt_bytes(stmt, 2);
		valdouble = ksql_stmt_double(stmt, 3);

		printf("Step (%zu:1): %" PRId64 "\n", i, valint);
		printf("Step (%zu:2): %s\n", i,
			NULL == valstr ? "(null)" : valstr);
		if (NULL == valblob) 
			printf("Step (%zu:3): null\n", i);
		else
			printf("Step (%zu:3): [%.*s] (%zu)\n", i,
				(int)valblobsz, 
				(const char *)valblob, valblobsz);
		printf("Step (%zu:4): %f\n", i, valdouble);
		printf("Step (%zu): expecting null: %d\n", i, nulls[i]);

		assert(i < insertsz * 2);

		if (nulls[i++])
			continue;

		if (KSQL_OK != ksql_result_isnull(stmt, &isnull, 0))
			errx(EXIT_FAILURE, "ksql_result_isnull");
		if (isnull)
			errx(EXIT_FAILURE, "ksql_result_isnull wrong");
		if (KSQL_OK != ksql_result_isnull(stmt, &isnull, 1))
			errx(EXIT_FAILURE, "ksql_result_isnull");
		if (isnull)
			errx(EXIT_FAILURE, "ksql_result_isnull wrong");
		if (KSQL_OK != ksql_result_isnull(stmt, &isnull, 3))
			errx(EXIT_FAILURE, "ksql_result_isnull");
		if (isnull)
			errx(EXIT_FAILURE, "ksql_result_isnull wrong");

		if (KSQL_OK != ksql_result_int(stmt, &valint2, 0))
			errx(EXIT_FAILURE, "ksql_result_int");
		if (valint != valint2)
			errx(EXIT_FAILURE, "ksql_result_int inequality");
		if (KSQL_OK != ksql_result_str(stmt, &valstr2, 1))
			errx(EXIT_FAILURE, "ksql_result_str");
		if ((NULL == valstr && NULL != valstr2) ||
		    (NULL != valstr && NULL == valstr2) ||
		    (NULL != valstr && strcmp(valstr, valstr2)))
			errx(EXIT_FAILURE, "ksql_result_str inequality");
		if (KSQL_OK != ksql_result_blob(stmt, &valblob2, &valblobsz2, 2))
			errx(EXIT_FAILURE, "ksql_result_blob");
		if ((NULL == valblob && NULL != valblob2) ||
		    (NULL != valblob && NULL == valblob2) ||
		    (valblobsz != valblobsz2) ||
		    (NULL != valblob && memcmp(valblob, valblob2, valblobsz2)))
			errx(EXIT_FAILURE, "ksql_result_blob inequality");
		if (KSQL_OK != ksql_result_double(stmt, &valdouble2, 3))
			errx(EXIT_FAILURE, "ksql_result_double");
		if (valdouble != valdouble2)
			errx(EXIT_FAILURE, "ksql_result_double inequality");
	}

	if (KSQL_OK != ksql_stmt_free(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_free");
	if (KSQL_OK != ksql_close(sql))
		errx(EXIT_FAILURE, "ksql_close");

	ksql_free(sql);
	return EXIT_SUCCESS;
}
