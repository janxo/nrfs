#ifndef __info__
#define __info__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>




#define RAID1 1
#define RAID5 5
#define RAID1_MAIN 0
#define RAID1_REPLICANT 1
 
#define ATTR_HASH "user.hash"

#define ZIPFILE "/zipfile.tar.gz"

#define FUSE_BUFF_LEN 4096

#define NAME_LEN 64
#define MAX_SERVERS 16
#define MAX_STORAGES 10
#define ADDR_LEN 32
#define PORT_LEN 8
#define CACHE_LEN 10
#define BUFF_len 32768	//32KB
#define READ_CHUNK_LEN 32768


typedef enum {dummy = -123495, unused = -50, success = 0, error = -1, done = 1,
			  writing = 2, hash_match = 4, hash_mismatch = -4, no_attr = -5, 
			  sending_attr = 5, send_to_server = 10, receive_from_server = -10} status;

typedef enum {cmd_getattr, cmd_access, cmd_utimens, cmd_unlink, cmd_release,
			  cmd_create, cmd_open, cmd_readdir, cmd_read, cmd_write, cmd_truncate,
			  cmd_mkdir, cmd_rmdir, cmd_rename, cmd_restore_file, cmd_restore_dir} command;



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
	size_t f_size;
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