#define FUSE_USE_VERSION 26

#include <fuse.h>
#include "info.h"
#include "parse.h"






int main(int argc, char *argv[]) {

	printf("FREEE\n");
	printf("storage %s\n", argv[2]);

	strg_info_t strg;
	printf("storage size -- %d\n", sizeof(strg));
	init_storage(argv[1], argv[2], &strg);

	test_storage(&strg);
	return 0;
}