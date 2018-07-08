#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "parse.h"
#include "info.h"
#include "tst.h"


#define FUSE_EXEC "fuse_client"


// static void run_storage(storage *stor, char *config);
// static void init(info *inf, char *path);



// static void run_storage(storage *stor, char *config) {
// 	pid_t pid;

// 	pid = fork();
// 	int status;
// 	if (pid < 0) {
// 		fprintf(stderr, "Fork Failed");
		

// 	} else if (pid == 0) {
// 		char *args[4];
// 		char exec_file[32];
// 		strncpy(exec_file, FUSE_EXEC, sizeof(FUSE_EXEC));
// 		//printf("exec is -- %s\n", exec_file);
// 		args[0] = exec_file;
// 		args[1] = config;
// 		args[2] = stor->diskname;
// 		args[3] = NULL;
// 		execv(args[0], args);
// 	}

// 	wait(&status);
// }


// static void init(info *inf, char *path) {
// 	int nstorages = inf->storage_count;
// 	int i = 0;
// 	for (; i < nstorages; ++i) {
// 		run_storage(&inf->storages[i], path);
// 	}
	
// }

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "No Config File Provided\n");
		exit(-1);
	}


	char *names[10];
	int count = get_disknames(argv[1], names);


	int i = 0;
	for (; i < count; ++i)
	{
		printf("diskname -- %s\n", names[i]);
	}
	return 0;
}