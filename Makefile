CFLAGS=-c -Wall
CC=gcc
OUT=net_raid_client​ net_raid_server
FUSE=`pkg-config fuse --cflags --libs`

all: client server

client: client.o parse.o
	$(CC) net_raid_client.o parse.o -o net_raid_client​

server: server.o
	$(CC) net_raid_server.o -o net_raid_server

parse: parse.o
	$(CC) parse.o -o parse

client.o: net_raid_client.c
	$(CC) $(CFLAGS) $(FUSE) net_raid_client.c

server.o: net_raid_server.c
	$(CC) $(CFLAGS) net_raid_server.c

parse.o: parse.c
	$(CC) $(CFLAGS) parse.c

clean:
	rm *o $(OUT)