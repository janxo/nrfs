#ifndef __fuseclient__
#define __fuseclient__

#include "info.h"

request_t *build_req(int raid, command cmd, const char *path,
							struct fuse_file_info *fi, status st, size_t file_size, off_t offset, size_t padding_size);




#endif