CFLAGS=-c -Wall
CC=gcc
OUT=net_raid_client​ net_raid_server fuse_client
FUSE=`pkg-config fuse --cflags --libs`

all: client server fuse_client

client: client.o fuse_client.o parse.o tst.o
	$(CC) net_raid_client.o parse.o tst.o -o net_raid_client​

server: server.o
	$(CC) net_raid_server.o -o net_raid_server

fuse_client: client.o parse.o fuse_client.o tst.o
	$(CC) fuse_client.o parse.o tst.o -o fuse_client

parse: parse.o
	$(CC) parse.o -o parse

client.o: net_raid_client.c
	$(CC) $(CFLAGS) net_raid_client.c

server.o: net_raid_server.c
	$(CC) $(CFLAGS) net_raid_server.c

fuse_client.o: fuse_client.c
	$(CC) $(CFLAGS) $(FUSE) fuse_client.c

parse.o: parse.c
	$(CC) $(CFLAGS) parse.c

tst.o: tst.c
	$(CC) $(CFLAGS) tst.c

clean:
	rm *o *log $(OUT)