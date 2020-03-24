CC = gcc
CFLAGS = -Wall -fPIC

LDFLAGS = -L

build: libso_stdio.so

libso_stdio.so: so_stdio.o
	$(CC) -shared -o $@ $^

so_stdio.o: so_stdio.c so_stdio.h

clean:
	rm -f so_stdio.o libso_stdio.so