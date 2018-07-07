#ifndef __info__
#define __info__

#define NAME_LEN 64
#define MAX_SERVERS 16
#define MAX_STORAGES 10
#define ADDR_LEN 32
#define PORT_LEN 8

typedef struct remote {
	char ip_address[ADDR_LEN];
	char port[PORT_LEN];
}remote;

typedef struct storage {
	char diskname[NAME_LEN];
	char mountpoint[NAME_LEN];
	int server_count;
	char raid;
	remote servers[MAX_SERVERS];
	remote hotswap;
}storage;

typedef struct info {
	char errorlog[NAME_LEN];
	char cache_size[16];
	char cache_replacement[16];
	int timeout;
	int storage_count;
	storage storages[MAX_STORAGES];
}info;




#endif