#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
// #include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "rdwrn.h"
#include "info.h"
#include "parse.h"
#include "tst.h"



void init(strg_info_t *strg);
int init_connection(strg_info_t *strg);
char *get_time();
void build_req(request_t *req, int raid, command cmd, char *path,
							int padding_size, struct fuse_file_info *fi, int file_size);

int *socket_fds;
FILE *log_file;




char *get_time() {
	time_t current_time;
    char *c_time_string;

    /* Obtain current time. */
    current_time = time(NULL);

    if (current_time == ((time_t)-1)) {
        (void) fprintf(stderr, "Failure to obtain the current time.\n");
        exit(EXIT_FAILURE);
    }

    /* Convert to local time format. */
    c_time_string = ctime(&current_time);

    if (c_time_string == NULL) {
        (void) fprintf(stderr, "Failure to convert the current time.\n");
        exit(EXIT_FAILURE);
    }
	char *res = malloc(strlen(c_time_string)+2);
	res[0] = '[';
	strcpy(res+1, c_time_string);
	int len = strlen(res);
	res[len-1] = ']';
	res[len] = '\0';
	return res;   
}

void log_msg(FILE *log_file, strg_info_t *strg, remote *server, char *msg) {
	char *cur_time = get_time();
	fprintf(log_file, "%s %s %s:%s %s\n", cur_time, strg->strg.diskname,
								 server->ip_address, server->port, msg);
	free(cur_time);
}

/** initialize connection to servers */
int init_connection(strg_info_t *strg) {
	printf("IN client main\n");
	socket_fds = malloc(strg->strg.server_count*sizeof(int));
	int i = 0;
	for (;i < strg->strg.server_count; ++i) {
		int sfd;
		struct sockaddr_in addr;
	    int ip;
	    // char buf[1024];
	    sfd = socket(AF_INET, SOCK_STREAM, 0);
	    inet_pton(AF_INET, strg->strg.servers[i].ip_address, &ip);

	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(atoi(strg->strg.servers[i].port));
	    addr.sin_addr.s_addr = ip;

	    int success = connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	    if (success == 0) {
	    	socket_fds[i] = sfd;
	    	log_msg(log_file, strg, &strg->strg.servers[i], "open connection");
	    	// char *cur_time = get_time();
	    	// int len;
	    	// len = fprintf(log_file, "%s %s %s%s %s\n", cur_time, strg->strg.diskname, strg->strg.servers[i].ip_address, 
	    	// 										strg->strg.servers[i].port, "open connection");
	    	// printf("Connected successfully -- %d\n", len);
	    } else {
	    	fprintf(stderr, "%s\n", "FAILED TO CONNECT");
	    	return success;
	    }

	}
	return 0;
    // write(sfd, "qwe", 3);
    // read(sfd, &buf, 3);
    // printf("%s\n", buf);
    //sleep(600);
    // close(sfd);
}



void init(strg_info_t *strg) {
	log_file = fopen(strg->errorlog, "a");

	if (log_file == NULL) {
		fprintf(stderr, "LOG FILE NOT FOUND\n");
		exit(-1);
	}
	init_connection(strg);
}


static int nrfs1_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi) {
	request_t req;
	response_t resp;
	req.raid = RAID1;
	req.fn = cmd_readdir;

	build_req(&req, RAID1, cmd_readdir, path, 0, fi, 0);
	int sfd = socket_fds[RAID1_MAIN];
	printf("in client before write\n");
	write(sfd, &req, sizeof(request_t));
	printf("after write\n");
	int read_b = read(sfd, &resp, sizeof(resp));
	printf("after read\n");
	printf("read %d bytes\n", read_b);
	printf("status is -- %d\n", resp.st);
	printf("buff -- %s\n", resp.buff);
	// filler(buf, resp.buff, NULL, 0);
	char *tok;
	// tok = strtok(resp.buff, " ");

	
	while(tok != NULL) {
		filler(buf, tok, NULL, 0);
		tok = strtok(NULL, " ");
	}
	(void) offset;
	(void) fi;
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, "file1", NULL, 0);

	// printf("ls -- %s\n", resp.buff);


	return 0;
}

// static int nrfs1_creat(const char *path, mode_t mode, struct fuse_file_info *fi) {

// }

void build_req(request_t *req, int raid, command cmd, char *path,
							int padding_size, struct fuse_file_info *fi, int file_size) {
	req->raid = raid;
	req->fn = cmd;
	strcpy(req->f_info.path, path);
	req->f_info.padding_size = padding_size;
	req->f_info.flags = fi->flags;
	req->f_info.f_size = file_size;
}

static int nrfs1_write(const char *path, const char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi) {
	request_t req;
	req.raid = RAID1;
	req.fn = cmd_write;

	int fd = open(path, fi->flags);
	int sfd = socket_fds[RAID1_MAIN];

	strcpy(req.f_info.path, path);
	req.f_info.padding_size = 0;
	req.f_info.flags = fi->flags; 
	struct stat st;
	fstat(fd, &st);
	req.f_info.f_size = st.st_size;

	write(sfd, &req, sizeof(request_t));


	return 0;
}

static int nrfs1_open(const char *path, struct fuse_file_info *fi) {

	return 0;
}

static int nrfs1_getattr(const char *path, struct stat *stbuf) {
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
	}

	return res;
}

static struct fuse_operations nrfs1_oper = {
	.getattr	= nrfs1_getattr,
	.readdir	= nrfs1_readdir,
	.open		= nrfs1_open,
	// .read		= nrfs1_read,
	.write		= nrfs1_write,
};


static struct fuse_operations nrfs5_oper = {
	// .getattr	= nrfs1_getattr,
	// .readdir	= nrfs1_readdir,
	// .open		= nrfs1_open,
	// .read		= nrfs1_read,
};



int main(int argc, char *argv[]) {

	// printf("FREEE\n");
	// printf("storage %s\n", argv[2]);

	strg_info_t strg;
	
	init_storage(argv[1], argv[2], &strg);

	test_storage(&strg);
	init(&strg);
	// printf("DATE __ %s\n", get_time());
	int len = 32;
	char buff1[len];
	char buff2[len];
	char *buff3 = "-f";
	char *fuse_argv[4];
	
	strcpy(buff1, argv[0]);
	strcpy(buff2, strg.strg.mountpoint);

	fuse_argv[0] = buff1;
	fuse_argv[1] = buff2;
	fuse_argv[2] = buff3;
	fuse_argv[3] = NULL;

	struct fuse_operations *nrfs_oper;

	if (strg.strg.raid == RAID1) {
		nrfs_oper = &nrfs1_oper;
	} else if (strg.strg.raid == RAID5) {
		nrfs_oper = &nrfs5_oper;
	}
	fclose(log_file);
	return fuse_main(argc, fuse_argv, nrfs_oper, NULL);
	return 0;
}