#ifndef __info__
#define __info__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <openssl/md5.h>



#define RAID1 1
#define RAID5 5
#define RAID1_MAIN 0
#define RAID1_REPLICANT 1

#define ATTR_HASH "user.hash"

#define FUSE_BUFF_LEN 4096

#define NAME_LEN 64
#define MAX_SERVERS 16
#define MAX_STORAGES 10
#define ADDR_LEN 32
#define PORT_LEN 8
#define CACHE_LEN 10
#define BUFF_len 32768	//32KB
#define READ_CHUNK_LEN 32768


typedef enum {dummy = -123495, unused = -50, success = 0, error = -1, done = 1 , writing = 2, hash_match = 4, hash_mismatch = -4} status;

typedef enum {cmd_getattr, cmd_access, cmd_utimens, cmd_unlink,
			 cmd_create, cmd_open, cmd_readdir, cmd_read, cmd_write,
			 cmd_mkdir, cmd_rmdir, cmd_rename, cmd_restore} command;


typedef struct {
    uint32_t buf[4];
    uint32_t bits[2];
    unsigned char in[64];
} MD5Context_t;


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
	int fd;
	int mask;
	mode_t mode;
	off_t f_size;
	off_t offset;
	size_t padding_size;
} file_info;

typedef struct {
	int raid;
	command fn;
	status st;
	bool sendback;
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
	mode_t mode;
	char *file;
} cache_file_t;


#endif