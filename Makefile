.SUFFIXES: .3 .3.html .html .dot .svg .3.xml

include Makefile.configure

WWWDIR	 = /var/www/vhosts/kristaps.bsd.lv/htdocs/ksql
VMAJOR	!= grep 'define	KSQL_VMAJOR' ksql.h | cut -f3
VMINOR	!= grep 'define	KSQL_VMINOR' ksql.h | cut -f3
VBUILD	!= grep 'define	KSQL_VBUILD' ksql.h | cut -f3
VERSION	:= $(VMAJOR).$(VMINOR).$(VBUILD)
BUILT	 = index.css \
	   mandoc.css
HTMLS	 = ksql.3.html \
	   ksql_alloc.3.html \
	   ksql_alloc_child.3.html \
	   ksql_bind_double.3.html \
	   ksql_cfg_defaults.3.html \
	   ksql_close.3.html \
	   ksql_exec.3.html \
	   ksql_free.3.html \
	   ksql_lastid.3.html \
	   ksql_open.3.html \
	   ksql_result_double.3.html \
	   ksql_role.3.html \
	   ksql_stmt_alloc.3.html \
	   ksql_stmt_double.3.html \
	   ksql_stmt_free.3.html \
	   ksql_stmt_reset.3.html \
	   ksql_stmt_step.3.html \
	   ksql_trace.3.html \
	   ksql_trans_commit.3.html \
	   ksql_trans_open.3.html \
	   ksql_untrace.3.html
XMLS	 = ksql.3.xml \
	   ksql_alloc.3.xml \
	   ksql_alloc_child.3.xml \
	   ksql_bind_double.3.xml \
	   ksql_cfg_defaults.3.xml \
	   ksql_close.3.xml \
	   ksql_exec.3.xml \
	   ksql_free.3.xml \
	   ksql_lastid.3.xml \
	   ksql_open.3.xml \
	   ksql_result_double.3.xml \
	   ksql_role.3.xml \
	   ksql_stmt_alloc.3.xml \
	   ksql_stmt_double.3.xml \
	   ksql_stmt_free.3.xml \
	   ksql_stmt_reset.3.xml \
	   ksql_stmt_step.3.xml \
	   ksql_trace.3.xml \
	   ksql_trans_commit.3.xml \
	   ksql_trans_open.3.xml \
	   ksql_untrace.3.xml
MANS	 = ksql.3 \
	   ksql_alloc.3 \
	   ksql_alloc_child.3 \
	   ksql_bind_double.3 \
	   ksql_cfg_defaults.3 \
	   ksql_close.3 \
	   ksql_exec.3 \
	   ksql_free.3 \
	   ksql_lastid.3 \
	   ksql_open.3 \
	   ksql_result_double.3 \
	   ksql_role.3 \
	   ksql_stmt_alloc.3 \
	   ksql_stmt_double.3 \
	   ksql_stmt_free.3 \
	   ksql_stmt_reset.3 \
	   ksql_stmt_step.3 \
	   ksql_trace.3 \
	   ksql_trans_commit.3 \
	   ksql_trans_open.3 \
	   ksql_untrace.3
SRCS	 = $(MANS) \
	   bind.c \
	   compats.c \
	   extern.h \
	   log.c \
	   ksql.c \
	   ksql.h \
	   result.c \
	   stmt.c \
	   tests.c \
	   test.c \
	   test.sql \
	   trace.c \
	   trans.c \
	   Makefile
OBJS	 = bind.o \
	   ksql.o \
	   log.o \
	   result.o \
	   stmt.o \
	   trace.o \
	   trans.o

# FreeBSD's default .c.o doesn't recognise CPPFLAGS.
# CFLAGS += $(CPPFLAGS)

# Use this, for now, because we've marked functions as being deprecated
# but still use them internally.
CFLAGS += -Wno-deprecated-declarations

all: test libksql.a test.db

test: test.c compats.o libksql.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test.c compats.o libksql.a -lsqlite3 $(LDFLAGS)

test.db: test.sql
	rm -f $@
	sqlite3 $@ < test.sql 

libksql.a: $(OBJS) compats.o
	$(AR) rs $@ $(OBJS) compats.o

compats.o $(OBJS) test: config.h

$(OBJS): extern.h ksql.h

www: $(HTMLS) index.html ksql.svg ksql.tar.gz atom.xml

installwww: www
	mkdir -p $(WWWDIR)/snapshots
	$(INSTALL_DATA) atom.xml ksql.svg $(HTMLS) index.html $(BUILT) $(WWWDIR)
	$(INSTALL_DATA) ksql.tar.gz $(WWWDIR)/snapshots
	$(INSTALL_DATA) ksql.tar.gz $(WWWDIR)/snapshots/ksql-$(VERSION).tar.gz

ksql.tar.gz:
	mkdir -p .dist/ksql-$(VERSION)
	install -m 0644 $(SRCS) .dist/ksql-$(VERSION)
	install -m 0755 configure .dist/ksql-$(VERSION)
	( cd .dist && tar zvcf ../$@ . )
	rm -rf .dist

install: libksql.a
	mkdir -p $(DESTDIR)$(LIBDIR)
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	$(INSTALL_LIB) libksql.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) ksql.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) $(MANS) $(DESTDIR)$(MANDIR)/man3

clean:
	rm -f libksql.a compats.o $(OBJS) test test.db
	rm -f $(HTMLS) $(XMLS) index.html atom.xml ksql.tar.gz ksql.svg

distclean: clean
	rm -f Makefile.configure config.h config.log

.3.3.xml:
	( echo "<article data-sblg-article=\"1\" data-sblg-tags=\"manpage\">" ; \
	  mandoc -Ofragment -Thtml $< ; \
	  echo "</article>"; ) >$@

$(HTMLS): $(XMLS)
	sblg -t manpage.xml -L $(XMLS)

index.html: $(XMLS) index.xml versions.xml
	sblg -s date -t index.xml -o $@ versions.xml $(XMLS)

atom.xml: versions.xml
	sblg -s date -a versions.xml >$@

.dot.svg:
	dot -Tsvg $< | xsltproc --novalid notugly.xsl - >$@

