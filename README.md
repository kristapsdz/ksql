## Synopsis

ksql is a simple wrapper around the SQLite 
[C-language interface](https://www.sqlite.org/c3ref/intro.html).
It makes sure your database cleans up properly in the case of
application failure by using the
[atexit(3)](https://man.openbsd.org/atexit) facility.

It also has the facility to open the database in a protected child,
communicating with the caller via pipes.
This allows for stronger sandboxing of the calling process.

## Installation

Download the latest version's 
[source archive](https://kristaps.bsd.lv/ksql/snapshots/ksql.tar.gz) 
or download the project from GitHub.
Then run the configuration script with `./configure`.  (See the
[configure](https://github.com/kristapsdz/ksql/blob/master/configure)
script for details.)
Finally, compile with `make`, then `sudo make install` (or `doas make
install`, whatever the case may be).

## API Reference

See the [ksql(3) manpage](https://kristaps.bsd.lv/ksql/ksql.3.html) for
complete library documentation.

## License

All sources use the ISC (like OpenBSD) license.
See the [LICENSE.md](LICENSE.md) file for details.
