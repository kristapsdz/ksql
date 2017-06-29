.SUFFIXES: .3 .3.html .html .xml

include Makefile.configure

WWWDIR	 = /var/www/vhosts/kristaps.bsd.lv/htdocs/ksql
VERSION	 = 0.1.2
BUILT	 = index.css \
	   mandoc.css
HTMLS	 = index.html \
	   ksql.3.html \
	   ksql_alloc.3.html \
	   ksql_alloc_child.3.html \
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
	   ksql_trace.3.html \
	   ksql_trans_commit.3.html \
	   ksql_trans_open.3.html \
	   ksql_untrace.3.html
MANS	 = ksql.3 \
	   ksql_alloc.3 \
	   ksql_alloc_child.3 \
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
	   ksql_trace.3 \
	   ksql_trans_commit.3 \
	   ksql_trans_open.3 \
	   ksql_untrace.3
SRCS	 = $(MANS) \
	   ksql.c \
	   ksql.h \
	   compat_err.c \
	   compat_progname.c \
	   compat_reallocarray.c \
	   test-INFTIM.c \
	   test-SOCK_NONBLOCK.c \
	   test-arc4random.c \
	   test-capsicum.c \
	   test-err.c \
	   test-pledge.c \
	   test-progname.c \
	   test-reallocarray.c \
	   test-sandbox_init.c \
	   test.c \
	   test.sql \
	   Makefile
COMPAT	 = compat_err.o \
	   compat_progname.o \
	   compat_reallocarray.o

all: test libksql.a test.db

test: test.c $(COMPAT) libksql.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test.c $(COMPAT) libksql.a -lsqlite3 

test.db: test.sql
	rm -f $@
	sqlite3 $@ < test.sql 

libksql.a: ksql.o $(COMPAT)
	$(AR) rs $@ ksql.o $(COMPAT)

$(COMPAT) ksql.o test: config.h

www: $(HTMLS) ksql.tar.gz

installwww: www
	mkdir -p $(WWWDIR)/snapshots
	$(INSTALL_DATA) $(HTMLS) $(BUILT) $(WWWDIR)
	$(INSTALL_DATA) ksql.tar.gz $(WWWDIR)/snapshots
	$(INSTALL_DATA) ksql.tar.gz $(WWWDIR)/snapshots/ksql-$(VERSION).tar.gz

ksql.tar.gz:
	mkdir -p .dist/ksql-$(VERSION)
	install -m 0644 $(SRCS) .dist/ksql-$(VERSION)
	install -m 0755 configure .dist/ksql-$(VERSION)
	( cd .dist && tar zvcf ../$@ . )
	rm -rf .dist

ksql.o: ksql.h

install: libksql.a
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	mkdir -p $(MANDIR)/man3
	$(INSTALL_LIB) libksql.a $(LIBDIR)
	$(INSTALL_DATA) ksql.h $(INCLUDEDIR)
	$(INSTALL_DATA) $(MANS) $(MANDIR)/man3

clean:
	rm -f libksql.a $(COMPAT) ksql.o $(HTMLS) ksql.tar.gz test

distclean: clean
	rm -f Makefile.configure config.h config.log

.3.3.html:
	mandoc -Ostyle=mandoc.css -Thtml $< >$@

index.html: versions.xml

.xml.html:
	sblg -t $< -o $@ versions.xml
