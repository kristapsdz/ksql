.SUFFIXES: .3 .3.html .html .xml

include Makefile.configure

VERSION	 = 0.0.9
BUILT	 = index.css \
	   mandoc.css
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

all: test libksql.a

test: test.c libksql.a test.db config.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test.c libksql.a -lsqlite3 

test.db: test.sql
	rm -f $@
	sqlite3 $@ < test.sql 

libksql.a: ksql.o config.h
	$(AR) rs $@ ksql.o

www: $(HTMLS) ksql.tar.gz

installwww: www
	mkdir -p $(PREFIX)/snapshots
	$(INSTALL_DATA) $(HTMLS) $(BUILT) $(PREFIX)
	$(INSTALL_DATA) ksql.tar.gz $(PREFIX)/snapshots
	$(INSTALL_DATA) ksql.tar.gz $(PREFIX)/snapshots/ksql-$(VERSION).tar.gz

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
	$(INSTALL_LIB) libksql.a $(PREFIX)/lib
	$(INSTALL_DATA) ksql.h $(PREFIX)/include
	$(INSTALL_DATA) $(MANS) $(PREFIX)/man/man3

clean:
	rm -f libksql.a ksql.o $(HTMLS) ksql.tar.gz test

distclean: clean
	rm -f Makefile.configure config.h config.log

.3.3.html:
	mandoc -Ostyle=mandoc.css -Thtml $< >$@

index.html: versions.xml

.xml.html:
	sblg -t $< -o $@ versions.xml
