.SUFFIXES: .3 .3.html .html .xml

PREFIX	?= /usr/local
VERSION	 = 0.0.8
CFLAGS	+= -g -W -Wall
BUILT	 = index.css
HTMLS	 = index.html \
	   ksql.3.html \
	   ksql_alloc.3.html \
	   ksql_bind_double.3.html \
	   ksql_close.3.html \
	   ksql_exec.3.html \
	   ksql_free.3.html \
	   ksql_lastid.3.html \
	   ksql_open.3.html \
	   ksql_stmt_alloc.3.html \
	   ksql_stmt_double.3.html \
	   ksql_stmt_free.3.html \
	   ksql_stmt_reset.3.html \
	   ksql_trans_commit.3.html \
	   ksql_trans_open.3.html
MANS	 = ksql.3 \
	   ksql_alloc.3 \
	   ksql_bind_double.3 \
	   ksql_close.3 \
	   ksql_exec.3 \
	   ksql_free.3 \
	   ksql_lastid.3 \
	   ksql_open.3 \
	   ksql_stmt_alloc.3 \
	   ksql_stmt_double.3 \
	   ksql_stmt_free.3 \
	   ksql_stmt_reset.3 \
	   ksql_trans_commit.3 \
	   ksql_trans_open.3
SRCS	 = $(MANS) \
	   ksql.c \
	   ksql.h \
	   Makefile

libksql.a: ksql.o
	$(AR) rs $@ ksql.o

www: $(HTMLS) ksql.tar.gz

installwww: www
	mkdir -p $(PREFIX)/snapshots
	install -m 0444 $(HTMLS) $(BUILT) $(PREFIX)
	install -m 0444 ksql.tar.gz $(PREFIX)/snapshots
	install -m 0444 ksql.tar.gz $(PREFIX)/snapshots/ksql-$(VERSION).tar.gz

ksql.tar.gz:
	mkdir -p .dist/ksql-$(VERSION)
	install -m 0644 $(SRCS) .dist/ksql-$(VERSION)
	( cd .dist && tar zvcf ../$@ . )
	rm -rf .dist

ksql.o: ksql.h

install: libksql.a
	mkdir -p $(PREFIX)/lib
	mkdir -p $(PREFIX)/include
	mkdir -p $(PREFIX)/man/man3
	install -m 0444 libksql.a $(PREFIX)/lib
	install -m 0444 ksql.h $(PREFIX)/include
	install -m 0444 $(MANS) $(PREFIX)/man/man3

clean:
	rm -f libksql.a ksql.o $(HTMLS) ksql.tar.gz

.3.3.html:
	mandoc -Thtml $< >$@

index.html: versions.xml

.xml.html:
	sblg -t $< -o $@ versions.xml
