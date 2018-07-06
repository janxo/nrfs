#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "parse.h"
#include "info.h"



int main(int argc, char *argv[]) {

	info inf;
	inf.storage_count = 0;
	printf("%d\n", argc);
	printf("%s\n", argv[1]);
	//printf("%d\n", sizeof(inf));
	parse_config(&inf, argv[1]);
	return 0;
}