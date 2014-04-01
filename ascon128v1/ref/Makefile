CC = /usr/bin/gcc
CFLAGS = -O2 -funroll-loops -fomit-frame-pointer
INCPATH = -I.

all: demo

demo: demo.c ascon.c
	$(CC) $(INCPATH) $(CFLAGS) $^ -o $@

clean:
	-rm -rf demo
