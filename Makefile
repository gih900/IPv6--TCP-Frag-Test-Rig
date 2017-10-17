CC = cc
CFLAGS  = -g
INCLUDES = -I/usr/local/include -L/usr/local/lib
COMPILE  = $(CC) $(CFLAGS) $(INCLUDES)

all:	tcp-proxy-fragmentation

libavl.o: libavl.c libavl.h
	$(COMPILE) -g -c libavl.c

tcp-proxy-fragmentation:	tcp-proxy-fragmentation.c libavl.o
	$(COMPILE) -o tcp-proxy-fragmentation tcp-proxy-fragmentation.c libavl.o -lpcap -lz

