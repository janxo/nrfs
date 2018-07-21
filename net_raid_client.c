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


static void run_storage(char *config, char *diskname);
static void init(char *config, char **disknames, int size);



static void run_storage(char *config, char *diskname) {
	pid_t pid;

	pid = fork();
	int status;
	if (pid < 0) {
		fprintf(stderr, "Fork Failed");
		

	} else if (pid == 0) {
		char *args[4];
		char exec_file[32];
		strcpy(exec_file, FUSE_EXEC);
		args[0] = exec_file;
		args[1] = config;
		args[2] = diskname;
		args[3] = NULL;
		execv(args[0], args);
	}

	wait(&status);
}


static void init(char *config, char **disknames, int size) {
	int i = 0;
	for (; i < size; ++i) {
		run_storage(config, disknames[i]);
	}
	
}


void free_space(char **names, int size) {
	int i = 0;
	for (; i < size; ++i) {
		free(names[i]);
	}
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "No Config File Provided\n");
		exit(-1);
	}


	char *names[10];
	int count = get_disknames(argv[1], names);

	init(argv[1], names, count);
	free_space(names, count);

	return 0;
}