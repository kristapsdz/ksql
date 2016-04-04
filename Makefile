PREFIX	?= /usr/local
CFLAGS	+= -g -W -Wall
MANS	 = ksql_alloc.3 \
	   ksql_bind_double.3 \
	   ksql_close.3 \
	   ksql_exec.3 \
	   ksql_free.3 \
	   ksql_lastid.3 \
	   ksql_open.3 \
	   ksql_stmt_alloc.3 \
	   ksql_stmt_double.3 \
	   ksql_stmt_free.3 \
	   ksql_stmt_reset.3

libksql.a: ksql.o
	$(AR) rs $@ ksql.o

ksql.o: ksql.h

install: libksql.a
	mkdir -p $(PREFIX)/lib
	mkdir -p $(PREFIX)/include
	mkdir -p $(PREFIX)/man/man3
	install -m 0444 libksql.a $(PREFIX)/lib
	install -m 0444 ksql.h $(PREFIX)/include
	install -m 0444 $(MANS) $(PREFIX)/man/man3

clean:
	rm -f libksql.a ksql.o
