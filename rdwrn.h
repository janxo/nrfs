#ifndef __rdwrn__
#define __rdwrn__\

#include <sys/types.h>

ssize_t readn(int fd , void * buffer , size_t n);
ssize_t writen(int fd, void * buffer , size_t n);
size_t sendfilen(int out_fd, int in_fd, off_t offset, size_t count);


#endif