PREFIX	?= /usr/local
CFLAGS	+= -g -W -Wall

libksql.a: ksql.o
	$(AR) rs $@ ksql.o

ksql.o: ksql.h

install: libksql.a
	mkdir -p $(PREFIX)/lib
	mkdir -p $(PREFIX)/include
	install -m 0444 libksql.a $(PREFIX)/lib
	install -m 0444 ksql.h $(PREFIX)/include

clean:
	rm -f libksql.a ksql.o
