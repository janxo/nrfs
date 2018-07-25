#ifndef __info__
#define __info__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <openssl/md5.h>


#define RAID1 1
#define RAID5 5
#define RAID1_MAIN 0
#define RAID1_REPLICANT 1

#define SWAP_FILE ".swap"

#define FUSE_BUFF_LEN 4096

#define NAME_LEN 64
#define MAX_SERVERS 16
#define MAX_STORAGES 10
#define ADDR_LEN 32
#define PORT_LEN 8
#define CACHE_LEN 10
#define BUFF_len 32768	//32KB
// #define CACHED_FILE_MAX_LEN 0x40000000	//1GB
#define CACHED_FILE_MAX_LEN 0x8000000 //128MB

typedef enum {unused = -50, success = 0, error = -1, done = 1 , writing = 2, file_create = 7} status;

typedef enum {cmd_getattr, cmd_readdir, cmd_read, cmd_write} command;


typedef struct {
	unsigned char hash[MD5_DIGEST_LENGTH*2+1];
} md5_t;

typedef struct remote {
	char ip_address[ADDR_LEN];
	char port[PORT_LEN];
} remote;

typedef struct storage {
	char diskname[NAME_LEN];
	char mountpoint[NAME_LEN];
	int server_count;
	char raid;
	remote servers[MAX_SERVERS];
	remote hotswap;
} storage;



typedef struct strg_info {
	char errorlog[NAME_LEN];
	char cache_size[CACHE_LEN];
	char cache_replacement[CACHE_LEN];
	int timeout;
	storage strg;
} strg_info_t;


typedef struct file_info {
	char path[NAME_LEN];
	int flags;
	int padding_size;
	off_t f_size;
	off_t offset;
	md5_t md5;
} file_info;

typedef struct {
	int raid;
	command fn;
	status st;
	file_info f_info;
} request_t;


typedef struct {
	int packet_size;
	status st;
	char buff[BUFF_len];
} response_t;


typedef struct {
	size_t f_size;
	off_t offset;
	char *file;
} cache_file_t;



#endif