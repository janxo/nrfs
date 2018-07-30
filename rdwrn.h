#ifndef __rdwrn__
#define __rdwrn__\

#include <sys/types.h>
#include "info.h"

ssize_t readn(int fd , const void * buffer , size_t n);
ssize_t writen(int fd, const void * buffer , size_t n);
size_t sendfilen(int out_fd, int in_fd, off_t offset, size_t count);
void md5_tostr(unsigned char *digest, md5_t *md5);
void get_hash(void *buff, size_t size, md5_t *md5);


#endif