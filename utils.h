#ifndef __rdwrn__
#define __rdwrn__

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS  64

#include <sys/types.h>
#include <fuse.h>
#include "info.h"

ssize_t readn(int fd , const void * buffer , size_t n);
ssize_t writen(int fd, const void * buffer , size_t n);
size_t sendfilen(int out_fd, int in_fd, off_t *offset, size_t count);
void md5_tostr(unsigned char *digest, md5_t *md5);
void get_hash(void *buff, size_t size, md5_t *md5);
int init_server(int *fd, remote *server);
size_t send_file1(int out_fd, int in_fd, request_t *req, md5_t *md5);
char *get_time();

void build_req(request_t *req, int raid, command cmd, const char *path,
							struct fuse_file_info *fi, size_t file_size, off_t offset, size_t padding_size);


#endif