#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS  64

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include "rdwrn.h"
#include "info.h"
#include "parse.h"
#include "tst.h"
#include "fuse_client.h"



void init(strg_info_t *strg);
int init_connection(strg_info_t *strg);
char *get_time();

size_t get_f_size(int fd) {
	struct stat st;
	fstat(fd, &st);
	return st.st_size;
}

int *socket_fds;
strg_info_t strg;
FILE *log_file;
cache_file_t cached_file;
request_t *write_req;
// bool file_created = false;


// needed for fuse functions
// for local functions strg arg is explicitly passed
strg_info_t *strg_global;

void print_md5_sum(md5_t *md) {
	int i;
	for(i=0; i <MD5_DIGEST_LENGTH; i++) {
		printf("%02x",md->hash[i]);
 	}
}



static void get_hash(void *buff, size_t size, md5_t *md5) {
	printf("\nABOUT TO CALCULATE HASH\n\n");
	MD5((unsigned char*) buff, size, md5->hash);
	print_md5_sum(md5);
	char tmp[128];
	int i;
	for(i=0; i <MD5_DIGEST_LENGTH; i++) {
		sprintf(tmp+i*2, "%02x",md5->hash[i]);
	}
	printf("\n\n");
	printf("\nmd5 is -- %s\n", tmp);
	printf("len is -- %zu\n", strlen(tmp));
	// printf("digest len -- %d\n", strlen());
	memcpy(md5->hash, tmp, 2*MD5_DIGEST_LENGTH);
	md5->hash[2*MD5_DIGEST_LENGTH] = '\0';
	printf("\nmd5 is -- %s\n", md5->hash);
}

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

void log_msg(strg_info_t *strg, int nth_server, char *msg) {
	// log_file = fopen(strg->errorlog, "a");
	remote *server = &strg->strg.servers[nth_server];
	char *cur_time = get_time();
	fprintf(log_file, "%s %s %s:%s %s\n", cur_time, strg->strg.diskname,
								 server->ip_address, server->port, msg);
	free(cur_time);
	fflush(log_file);
	// fclose(log_file);
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
	    	log_msg(strg, i, "open connection");
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
	cached_file.f_size = 0;
	cached_file.offset = 0;
	cached_file.file = NULL;
	log_file = fopen(strg->errorlog, "a");
	if (log_file == NULL) {
		fprintf(stderr, "LOG FILE NOT FOUND\n");
		// exit(-1);
	}
	init_connection(strg);
}


static int nrfs1_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi) {

	printf("nfrfs1_readdir\n");
	log_msg(&strg, RAID1_MAIN, "readdir");
	request_t *req;
	response_t resp;

	req = build_req(RAID1, cmd_readdir, path, fi, unused, 0, 0, 0);
	int sfd = socket_fds[RAID1_MAIN];
	writen(sfd, req, sizeof(request_t));

	status st;
	readn(sfd, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd, &res, sizeof(res));
		free(req);
		return -res;

	} else {

		memset(resp.buff, 0, sizeof(resp.buff));
		int read_b = readn(sfd, &resp.packet_size, sizeof(resp.packet_size));

		read_b = readn(sfd, resp.buff, resp.packet_size);

		// means server fd was closed
		if (read_b == -1) {
			printf("SERVER DEAD\n");
			// TODO
			// reconnect to server
		}

		char *tok;
		tok = strtok(resp.buff, ",");
	
		while(tok != NULL) {
			filler(buf, tok, NULL, 0);
			printf("tok -- %s\n", tok);
			tok = strtok(NULL, ",");
		}
	}

	free(req);
	return 0;
}



request_t *build_req(int raid, command cmd, const char *path,
							struct fuse_file_info *fi, status st, size_t file_size, off_t offset, size_t padding_size) {
	request_t *req = malloc(sizeof(request_t));
	req->raid = raid;
	req->fn = cmd;

	strcpy(req->f_info.path, path);
	req->st = st;
	if (fi != NULL) {
		req->f_info.padding_size = padding_size;
		req->f_info.flags = fi->flags;
		req->f_info.f_size = file_size;
		req->f_info.offset = offset;
	}
	return req;
}



void free_cached(cache_file_t *cach_file) {
	cach_file->f_size = 0;
	cach_file->offset = 0;
	cach_file->mode = 0;
	if (cach_file->file != NULL) {
		free(cach_file->file);
		cach_file->file = NULL;
	}
}



static status send_file(int sfd, request_t *req, const char *buf) {

	// send request to server
	writen(sfd, req, sizeof(request_t));
	printf("errno -- %d\n", errno);
	errno = 1234;
	printf("errno -- %d\n", errno);
	status st;

	// read file open status from server
	readn(sfd, &st, sizeof(status));
	
	if (st == error) {
		// read errno
		readn(sfd, &errno, sizeof(int));
		printf("errno -- %d\n", errno);
		errno = st;
		return st;
	} else {
		// char cache[size];
		// memcpy(cache, buf, size);
		printf("should send -- %zu bytes\n", req->f_info.f_size);

		md5_t md5;
		void *file_chunk = (void *) buf;
		get_hash(file_chunk, req->f_info.f_size, &md5);
		printf("md5 hash size -- %zu\n", sizeof(md5.hash));
		writen(sfd, &md5, sizeof(md5.hash));
		writen(sfd, buf, req->f_info.f_size);
		printf("sent -- %s\n", buf);

		readn(sfd, &st, sizeof(status));
		if (st == error) {
			readn(sfd, &errno, sizeof(int));
			printf("error writing file -- %d\n", -errno);
			return st;
		}
	}

	return st;
}

/** 
 * accumulates data in swap file. if it's last chunk sends data first to main server
 * and when receives status 'done' sends data to the replicant server
 */
static int nrfs1_write(const char *path, const char *buf, size_t size, off_t offset,
														struct fuse_file_info *fi) {
	printf("nrfs1_write\n");

	if (fi == NULL) {
		printf("FI is NULL\n");
	}
	printf("read flag -- %d\n", O_RDONLY);
	printf("wrtie flag -- %d, %d\n", O_WRONLY, O_RDWR);
	printf("fi flags before -- %d\n", fi->flags);

	request_t *req = build_req(RAID1, cmd_write, path, fi, unused, size, offset, 0);
	req->f_info.flags |= O_WRONLY;
	printf("fi flags after -- %d\n", req->f_info.flags);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	status st = send_file(sfd0, req, buf);

	if (st == error) {
		free(req);
		return -errno;
	}

	st = send_file(sfd1, req, buf);
	if (st == error) {
		free(req);
		return -errno;
	}

	free(req);
	return size;
}



static int nrfs1_open(const char *path, struct fuse_file_info *fi) {
	printf("nrfs1_open\n");
	if (fi == NULL) {
		printf("FI is NULL\n");
	}
	printf("path -- %s\n", path);
	request_t *req = build_req(RAID1, cmd_open, path, fi, unused, 0, 0, 0);
	
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));
	writen(sfd1, req, sizeof(request_t));

	status st;
	readn(sfd0, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}
	printf("open was successful\n");
	free(req);
	return 0;
}

static int nrfs1_getattr(const char *path, struct stat *stbuf) {
	printf("nrfs1_getattr\n");
	log_msg(&strg, RAID1_MAIN, "getattr");

	request_t *req = build_req(RAID1, cmd_getattr, path, NULL, unused, 0, 0, 0);

	int sfd = socket_fds[RAID1_MAIN];
	writen(sfd, req, sizeof(request_t));

	status st;
	readn(sfd, &st, sizeof(st));


	if (st == error) {
		printf("STATUS -- %d\n", st);
		
		int res;
		// printf("sizeof errno is -- %lu\n", sizeof(errno));
		readn(sfd, &res, sizeof(res));
		printf("errno -- %d\n", res);
		free(req);
		return -res;
	} else {
		readn(sfd, stbuf, sizeof(struct stat));
	}
	// printf("st_mode2 -- %d\n", stbuf->st_mode);
	// printf("sizeof stbuf -- %zu\n", sizeof(struct stat));
	printf("st size -- %zu\n", stbuf->st_size);
	printf("nrfs1_getattr DONE\n");
	
	free(req);
	return 0;
}

static void* nrfs1_init(struct fuse_conn_info *conn) {
	printf("nrfs1_init\n");

	return NULL;
}

static void nrfs1_destroy(void* private_data) {
	printf("nrfs1_destroy\n");
}

static int nrfs1_read(const char* path, char *buf, size_t size, off_t offset,
											 struct fuse_file_info* fi) {
	printf("nrfs1_read\n");
	request_t *req = build_req(RAID1, cmd_read, path, fi, unused, size, offset, 0);
	
	req->f_info.flags |= O_RDONLY;

	int sfd0 = socket_fds[RAID1_MAIN];
	writen(sfd0, req, sizeof(request_t));
	// printf("request sent\n");
	status st;
	readn(sfd0, &st, sizeof(status));
	// printf("status -- %d\n", st);
	// printf("offset -- %lu\n", offset);
	// printf("shouldve read -- %zu\n", size);
	size_t read_n = 0;
	// TODO maybe try to read from second server
	// this time it just retunrs with errno
	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
		
	} else {
		
		char *tmp = malloc(sizeof(status)+READ_CHUNK_LEN);
		// printf("before read\n");
		status dum;
		int dummy_len = sizeof(status);
		
		// printf("should've read -- %zu\n", size);
		read_n = read(sfd0, tmp, dummy_len+READ_CHUNK_LEN);
		
		memcpy(&dum, tmp, dummy_len);
		// printf("dummy -- %d\n", dum);
		
		// printf("read -- %zu\n", read_n);
		read_n -= dummy_len;
		// printf("tmp -- %s\n", tmp);
		memcpy(buf, tmp+dummy_len, read_n);
		if (read_n == -1) read_n = -errno;

		free(tmp);
	}

	free(req);
	printf("\n !!! READ DONE !!!\n\n");
	return read_n;
}

static int nrfs1_release(const char* path, struct fuse_file_info *fi) {
	printf("nrfs1_release\n");

	return 0;
}


static int nrfs1_unlink(const char* path) {
	printf("nrfs1_unlink\n");

	request_t *req = build_req(RAID1, cmd_unlink, path, NULL, unused, 0, 0, 0);
	
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));
	writen(sfd1, req, sizeof(request_t));

	status st;
	readn(sfd0, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}

	free(req);
	return 0;
}

static int nrfs1_rmdir(const char* path) {
	printf("nrfs1_rmdir\n");

	request_t *req = build_req(RAID1, cmd_rmdir, path, NULL, unused, 0, 0, 0);

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));
	writen(sfd1, req, sizeof(request_t));

	status st;
	readn(sfd0, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}

	free(req);
	return 0;
}


static int nrfs1_mkdir(const char* path, mode_t mode) {
	printf("nrfs1_mkdir\n");

	request_t *req = build_req(RAID1, cmd_mkdir, path, NULL, unused, 0, 0, 0);
	req->f_info.mode = mode;
	// printf("mode -- %d\n", mode);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));
	writen(sfd1, req, sizeof(request_t));

	status st;
	readn(sfd0, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}

	free(req);
	return 0;
}

static int nrfs1_opendir(const char* path, struct fuse_file_info* fi) {
	printf("nrfs1_opendir\n");

	return 0;
}

static int nrfs1_releasedir(const char* path, struct fuse_file_info *fi) {
	printf("nrfs1_releasedir\n");

	return 0;
}

static int nrfs1_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	printf("nrfs1_create\n");
	// printf("mode -- %d\n", mode);
	request_t *req = build_req(RAID1, cmd_create, path, fi, unused, 0, 0, 0);
	cached_file.mode = mode;
	req->f_info.mode = mode;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));
	writen(sfd1, req, sizeof(request_t));

	status st;
	readn(sfd0, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}


	// file_created = true;
	free(req);
	return 0;
}

static int nrfs1_truncate(const char *path, off_t size) {
	printf("nrfs1_truncate\n");

	return 0;
}

static int nrfs1_access(const char *path, int mask)
{
	printf("nrfs1_access\n");
	request_t *req = build_req(RAID1, cmd_access, path, NULL, unused, 0, 0, 0);
	req->f_info.mask = mask;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));
	writen(sfd1, req, sizeof(request_t));

	status st;
	readn(sfd0, &st, sizeof(status));

	if (st == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}

	free(req);
	return 0;
}


void cleanup() {
	fclose(log_file);
}


static int nrfs1_utimens(const char* path, const struct timespec ts[2]) {
	printf("nrfs1_utimens\n");
	request_t *req = build_req(RAID1, cmd_utimens, path, NULL, unused, 0, 0, 0);
	req->f_info.mask = AT_SYMLINK_NOFOLLOW;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	writen(sfd0, req, sizeof(request_t));
	writen(sfd0, ts, 2*sizeof(struct timespec));

	writen(sfd1, req, sizeof(request_t));
	writen(sfd1, ts, 2*sizeof(struct timespec));

	status stat;
	readn(sfd0, &stat, sizeof(status));

	if (stat == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}

	free(req);
	return 0;
}

static int nrfs1_rename(const char *from, const char *to) {
	printf("nrfs1_rename\n");

	request_t *req = build_req(RAID1, cmd_rename, from, NULL, unused, 0, 0, 0);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	size_t len = strlen(to);

	writen(sfd0, req, sizeof(request_t));
	writen(sfd0, &len, sizeof(size_t));
	writen(sfd0, to, len);

	writen(sfd1, req, sizeof(request_t));
	writen(sfd1, &len, sizeof(size_t));
	writen(sfd1, to, len);

	status stat;
	readn(sfd0, &stat, sizeof(status));

	if (stat == error) {
		int res;
		readn(sfd0, &res, sizeof(res));
		printf("error -- %d\n", -res);
		free(req);
		return -res;
	}

	free(req);

	return 0;
}

static struct fuse_operations nrfs1_oper = {
    .init        = nrfs1_init,
    .destroy     = nrfs1_destroy,
    .getattr     = nrfs1_getattr,
 //    .fgetattr    = nrfs1_fgetattr,
    .access      = nrfs1_access,
 //    .readlink    = nrfs1_readlink,
    .readdir     = nrfs1_readdir,
 //    .mknod       = nrfs1_mknod,
    .mkdir       = nrfs1_mkdir,
 //    .symlink     = nrfs1_symlink,
    .unlink      = nrfs1_unlink,
    .rmdir       = nrfs1_rmdir,
    .rename      = nrfs1_rename,
 //    .link        = nrfs1_link,
 //    .chmod       = nrfs1_chmod,
 //    .chown       = nrfs1_chown,
    .truncate    = nrfs1_truncate,
 //    .ftruncate   = nrfs1_ftruncate,
    .utimens     = nrfs1_utimens,
    .create      = nrfs1_create,
    .open        = nrfs1_open,
    .read        = nrfs1_read,
    .write       = nrfs1_write,
 //    .statfs      = nrfs1_statfs,
    .release     = nrfs1_release,
    .opendir     = nrfs1_opendir,
    .releasedir  = nrfs1_releasedir,
 //    .fsync       = nrfs1_fsync,
 //    .flush       = nrfs1_flush,
 //    .fsyncdir    = nrfs1_fsyncdir,
 //    .lock        = nrfs1_lock,
 //    .bmap        = nrfs1_bmap,
 //    .ioctl       = nrfs1_ioctl,
 //    .poll        = nrfs1_poll,
	// .setxattr    = nrfs1_setxattr,
 //    .getxattr    = nrfs1_getxattr,
 //    .listxattr   = nrfs1_listxattr,
 //    .removexattr = nrfs1_removexattr,
};


static struct fuse_operations nrfs5_oper = {
	// .getattr	= nrfs1_getattr,
	// .readdir	= nrfs1_readdir,
	// .open		= nrfs1_open,
	// .read		= nrfs1_read,
};


/**
 * expected args:
 * argv[0] - exec name
 * argv[1] - config file
 * argv[2] - storage name
 */

int main(int argc, char *argv[]) {

	// printf("FREEE\n");
	// printf("storage %s\n", argv[2]);

	
	// strg_global = &strg;

	init_storage(argv[1], argv[2], &strg);

	test_storage(&strg);
	init(&strg);
	// printf("DATE __ %s\n", get_time());
	int len = 32;
	char buff0[len];
	char buff1[len];
	char *buff2 = "-f";
	char *buff3 = "-s";
	// char *buff4 = "nonempty";

	argc = 4;
	char *fuse_argv[argc];
	
	strcpy(buff0, argv[0]);
	strcpy(buff1, strg.strg.mountpoint);

	fuse_argv[0] = buff0;
	fuse_argv[1] = buff1;
	fuse_argv[2] = buff2;
	fuse_argv[3] = buff3;
	// fuse_argv[4] = buff4;
	// fuse_argv[3] = NULL;

	struct fuse_operations *nrfs_oper;

	if (strg.strg.raid == RAID1) {
		nrfs_oper = &nrfs1_oper;
	} else if (strg.strg.raid == RAID5) {
		nrfs_oper = &nrfs5_oper;
	}
	// fclose(log_file);
	umask(0);
	int fuse_res = fuse_main(argc, fuse_argv, nrfs_oper, NULL);

	cleanup();
	printf("EXIT BOIIIIIIII\n");
	return fuse_res;
	
}