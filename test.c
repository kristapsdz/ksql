#include "config.h"

#if HAVE_ERR
# include <err.h>
#endif
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ksql.h"

int
main(void)
{
	struct ksql	*sql;
	struct ksqlcfg	 cfg;
	size_t		 i;
	struct ksqlstmt	*stmt;
	char		 buf[64];
	uint32_t	 val;

#ifndef HAVE_ARC4RANDOM
	srandom(getpid());
#endif

	memset(&cfg, 0, sizeof(struct ksqlcfg));
	cfg.flags = KSQL_EXIT_ON_ERR | KSQL_SAFE_EXIT;
	cfg.err = ksqlitemsg;
	cfg.dberr = ksqlitedbmsg;

	if (NULL == (sql = ksql_alloc_secure(&cfg, NULL, NULL)))
		errx(EXIT_FAILURE, "ksql_alloc_secure");

	if (KSQL_OK != ksql_open(sql, "test.db"))
		errx(EXIT_FAILURE, "ksql_open");

	if (KSQL_OK != ksql_stmt_alloc(sql, &stmt, "INSERT INTO numbers (foo,bar) VALUES (?,?)", 1))
		errx(EXIT_FAILURE, "ksql_stmt_alloc");
	for (i = 0; i < 10; i++) {
#ifdef HAVE_ARC4RANDOM
		val = arc4random();
#else
		val = random();
#endif
		warnx("binding: (1): %" PRIu32, val);
		if (KSQL_OK != ksql_bind_int(stmt, 0, val))
			errx(EXIT_FAILURE, "ksql_bind_int");
#ifdef HAVE_ARC4RANDOM
		val = arc4random();
#else
		val = random();
#endif
		snprintf(buf, sizeof(buf), "%" PRIu32, val);
		if (buf[0] < '5') {
			warnx("binding: (2): %s", buf);
			if (KSQL_OK != ksql_bind_str(stmt, 1, buf))
				errx(EXIT_FAILURE, "ksql_bind_str");
		} else {
			warnx("binding: (2): ----");
			if (KSQL_OK != ksql_bind_null(stmt, 1))
				errx(EXIT_FAILURE, "ksql_bind_null");
		}
		if (KSQL_DONE != ksql_stmt_step(stmt))
			errx(EXIT_FAILURE, "ksql_stmt_step");
		if (KSQL_OK != ksql_stmt_reset(stmt))
			errx(EXIT_FAILURE, "ksql_stmt_reset");
	}
	if (KSQL_OK != ksql_stmt_free(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_free");

	if (KSQL_OK != ksql_stmt_alloc(sql, &stmt, "SELECT foo,bar,id FROM numbers", 0))
		errx(EXIT_FAILURE, "ksql_stmt_alloc");
	while (KSQL_ROW == ksql_stmt_step(stmt)) {
		warnx("step (1): %" PRId64, ksql_stmt_int(stmt, 0));
		warnx("step (2): %s", ksql_stmt_str(stmt, 1));
		warnx("step (3): %" PRId64, ksql_stmt_int(stmt, 2));
	}
	if (KSQL_OK != ksql_stmt_free(stmt))
		errx(EXIT_FAILURE, "ksql_stmt_free");

	if (KSQL_OK != ksql_close(sql))
		errx(EXIT_FAILURE, "ksql_close");

	ksql_free(sql);
	return(EXIT_SUCCESS);
}
