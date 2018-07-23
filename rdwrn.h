#ifndef __rdwrn__
#define __rdwrn__\

#include <sys/types.h>

ssize_t readn(int fd , void * buffer , size_t n);
ssize_t writen(int fd, void * buffer , size_t n);


#endif