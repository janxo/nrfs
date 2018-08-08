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
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include "utils.h"
#include "info.h"
#include "parse.h"
#include "tst.h"


void init(strg_info_t *strg);
int init_connection(strg_info_t *strg);
char *get_time();


typedef struct {
	MD5_CTX md5_cont;
	md5_t md5;
	unsigned char digest[16];
	char name[NAME_LEN];
} md5_attr_t;


int *socket_fds;		// soccket file decriptors
strg_info_t strg;		// global storage info
FILE *log_file;			// log file_chun
md5_attr_t *md5_attr;	// used for hashing
int dead_server;		// index of dead server


int get_working_server() {
	int working_server;
	if (dead_server == -1)
		working_server = RAID1_MAIN;
	else
		working_server = 1 - dead_server;
	return working_server;
}


void log_msg(FILE *f, char *msg) {
	fprintf(f, "%s\n", msg);
	fflush(f);
}

void log_server_info(FILE *f, strg_info_t *strg, int nth_server) {
	remote *server = &strg->strg.servers[nth_server];
	char *cur_time = get_time();
	fprintf(f, "%s %s %s:%s ", cur_time, strg->strg.diskname,
								 server->ip_address, server->port);
	free(cur_time);
	fflush(f);
}

void *reconnect(void *data) {
	printf("timeout -- %d\n", strg.timeout);
	printf("server to reconnect -- %d\n", dead_server);
	clock_t begin;
	double time_spent;
	unsigned int i;
 	/* Mark beginning time */
	begin = clock();
	for (i=0; 1; i++) {
		printf("trying to reconnect\n");
		int res = init_server(&socket_fds[dead_server], &strg.strg.servers[dead_server]);
		if (res == 0) {
			dead_server = -1;
			break;
		}
		/* Get CPU time since loop started */
		time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
		if (time_spent >= strg.timeout);
			printf("couldn't reconnect\n");
			break;
	}
	pthread_exit(NULL);
}

 void try_reconnect() {
	printf("In try_reconnect\n");
	pthread_t t;
	pthread_create(&t, NULL, reconnect, NULL);
}


/** initialize connection to servers */
int init_connection(strg_info_t *strg) {
	printf("IN client main\n");
	socket_fds = malloc(strg->strg.server_count*sizeof(int));
	int i;
	for (i = 0; i < strg->strg.server_count; ++i) {
		int res = init_server(&socket_fds[i], &strg->strg.servers[i]);
		if (res == 0) {
			log_server_info(log_file, strg, i);
			log_msg(log_file, "open connection");
		}
	}
	return 0;
}



void init(strg_info_t *strg) {
	md5_attr = NULL;
	dead_server = -1;
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
	log_server_info(log_file, &strg, RAID1_MAIN);
	log_msg(log_file, "readdir");
	request_t *req;
	response_t resp;

	req = build_req(RAID1, cmd_readdir, path, fi, 0, 0, 0);
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




static int nrfs1_write(const char *path, const char *buf, size_t size, off_t offset,
														struct fuse_file_info *fi) {
	printf("nrfs1_write\n");

	if (fi == NULL) {
		printf("FI is NULL\n");
	}


	request_t *req = build_req(RAID1, cmd_write, path, fi, size, offset, 0);
	req->f_info.flags |= O_WRONLY;
	req->sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	md5_t md5;
	

	// void *file_chunk = (void *) buf;
	// get_hash(file_chunk, req->f_info.f_size, &md5);

	
	if (md5_attr == NULL) {
		md5_attr = malloc(sizeof(md5_attr_t));
		strcpy(md5_attr->name, path);
		MD5_Init(&md5_attr->md5_cont);
	}
	assert(md5_attr != NULL);
	
	MD5_Update(&md5_attr->md5_cont, buf, size);

	// printf("hash0 --- %s\n", md5.hash);
	// printf("hash1 --- %s\n", md5_1.hash);
	// int i;
	// for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", digest[i]);
 //   	printf("\n");
	int err;
	status st = send_file(sfd0, req, buf, &md5, &err);

	if (st == error) {
		free(req);
		return -err;
	}

	st = send_file(sfd1, req, buf, &md5, &err);
	if (st == error) {
		free(req);
		return -err;
	}

	free(req);
	return size;
}


void restore_file(request_t *restore_req, int from) {
	restore_req->f_info.mode = send_to_server;
	writen(from, restore_req, sizeof(request_t));
	writen(from, &strg.strg.servers[RAID1_REPLICANT], sizeof(remote));
}

static int nrfs1_open(const char *path, struct fuse_file_info *fi) {
	printf("nrfs1_open\n");
	if (fi == NULL) {
		printf("FI is NULL\n");
	}
	printf("path -- %s\n", path);
	request_t *req = build_req(RAID1, cmd_open, path, fi, 0, 0, 0);
	
	if (dead_server == -1) {
		int sfd0 = socket_fds[RAID1_MAIN];
		int sfd1 = socket_fds[RAID1_REPLICANT];
		writen(sfd0, req, sizeof(request_t));
		writen(sfd1, req, sizeof(request_t));


		status st0;
		status st1;

		readn(sfd0, &st0, sizeof(status));
		readn(sfd1, &st1, sizeof(status));
		printf("st0 -- %d\n", st0);
		printf("st1 -- %d\n", st1);

		md5_t md5_0;
		md5_t md5_1;

		request_t *restore_req = build_req(RAID1, cmd_restore_file, path, NULL, 0, 0, 0);

		// both server have file with attributes
		if (st0 == st1 && st0 == sending_attr) {
			status hash0_match;
			status hash1_match;
			// read hash match statuses from servers
			readn(sfd0, &hash0_match, sizeof(status));
			readn(sfd1, &hash1_match, sizeof(status));

			printf("hash0_match -- %d\n", hash0_match);
			printf("hash1_match -- %d\n", hash1_match);
			// printf("getting hashes\n");
			// check hashes if both open was successfull
			

			readn(sfd0, &md5_0.hash, sizeof(md5_0.hash));
			readn(sfd1, &md5_1.hash, sizeof(md5_1.hash));

			// compare returned hashes
			int res = strcmp((const char*)md5_0.hash, (const char*)md5_1.hash);

			
			if (hash0_match == hash1_match && hash0_match == hash_match) {

				if (res == 0) {
					printf("both hashes matched\n");

				} else {	
					printf("should copy from server0 to server1\n");

					// writen(sfd0, restore_req, sizeof(request_t));
					// writen(sfd0, &strg.strg.servers[RAID1_REPLICANT], sizeof(remote));
					restore_file(restore_req, sfd0);
				
				}

			} else if (hash0_match == hash_match && hash1_match != hash_match) {
				// match = hash_match;
				printf("hash0 mathed but hash1 did not\n");
				printf("should copy from server0 to server1\n");

				// writen(sfd0, restore_req, sizeof(request_t));
				// writen(sfd0, &strg.strg.servers[RAID1_REPLICANT], sizeof(remote));
				restore_file(restore_req, sfd0);

			} else if (hash1_match == hash_match && hash0_match != hash_match) {
				printf("hash1 matched but hash0 did not\n");
				printf("should copy from server1 to server0\n");

				// writen(sfd1, restore_req, sizeof(request_t));
				// writen(sfd1, &strg.strg.servers[RAID1_MAIN], sizeof(remote));
				restore_file(restore_req, sfd1);
			}

		} else {
			if (st0 == no_attr && st1 != no_attr) {
				printf("server0 no attr\n");
				printf("should copy from server1 to server0\n");
				readn(sfd1, &md5_1.hash, sizeof(md5_1.hash));
				restore_file(restore_req, sfd1);

			} else if (st0 != no_attr && st1 == no_attr) {
				printf("server1 no attr\n");
				printf("should copy from server0 to server1\n");
				readn(sfd0, &md5_0.hash, sizeof(md5_0.hash));
				restore_file(restore_req, sfd0);
			}
		}

	} else {
		// some of the server's dead
		printf("in open else \n");
		int sfd = 1-dead_server;
		status st;
		readn(sfd, &st, sizeof(status));
		if (st == error) {
			int res;
			readn(sfd, &res, sizeof(res));
			printf("error -- %d\n", -res);
			free(req);
			return -res;
		}
	}


	printf("open was successful\n");
	free(req);
	return 0;
}

static int nrfs1_getattr(const char *path, struct stat *stbuf) {
	printf("nrfs1_getattr\n");
	printf("path -- %s\n", path);
	log_server_info(log_file, &strg, RAID1_MAIN);
	log_msg(log_file, "getattr");

	request_t *req = build_req(RAID1, cmd_getattr, path, NULL, 0, 0, 0);


	int sfd = socket_fds[RAID1_MAIN];
	// int sfd1 = socket_fds[RAID1_REPLICANT];
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
	request_t *req = build_req(RAID1, cmd_read, path, fi, size, offset, 0);
	
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
	printf("path -- %s\n", path);
	if (md5_attr != NULL && strcmp(md5_attr->name, path) == 0) {
		printf("sending hashes\n");
		request_t *req = build_req(RAID1, cmd_release, path, NULL, 0, 0, 0);
		req->sendback = false;
		int sfd0 = socket_fds[RAID1_MAIN];
		int sfd1 = socket_fds[RAID1_REPLICANT];

		MD5_Final(md5_attr->digest, &md5_attr->md5_cont);
		md5_tostr(md5_attr->digest, &md5_attr->md5);
		printf("hash --- %s\n", md5_attr->md5.hash);
		writen(sfd0, req ,sizeof(request_t));
		writen(sfd0, &md5_attr->md5, sizeof(md5_attr->md5));

		writen(sfd1, req, sizeof(request_t));
		writen(sfd1, &md5_attr->md5, sizeof(md5_attr->md5));


		free(md5_attr);
		md5_attr = NULL;

		free(req);
	} 


	// for testing purposes
	// int sfd0 = socket_fds[RAID1_MAIN];

	// request_t *req = build_req(RAID1, cmd_restore_dir, path, NULL, 0, 0, 0);
	// req->f_info.mode = send_to_server;
	// writen(sfd0, req, sizeof(request_t));
	// writen(sfd0, &strg.strg.hotswap, sizeof(remote));
	
	return 0;
}


static int nrfs1_unlink(const char* path) {
	printf("nrfs1_unlink\n");

	request_t *req = build_req(RAID1, cmd_unlink, path, NULL, 0, 0, 0);
	req->sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));

	req->sendback = false;
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

	request_t *req = build_req(RAID1, cmd_rmdir, path, NULL, 0, 0, 0);
	req->sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));

	req->sendback = false;
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

	request_t *req = build_req(RAID1, cmd_mkdir, path, NULL, 0, 0, 0);
	req->f_info.mode = mode;
	req->sendback = true;
	// printf("mode -- %d\n", mode);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));

	req->sendback = false;
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
	request_t *req = build_req(RAID1, cmd_create, path, fi, 0, 0, 0);
	req->f_info.mode = mode;
	req->sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));

	req->sendback = false;
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

static int nrfs1_truncate(const char *path, off_t size) {
	printf("nrfs1_truncate\n");
	
	return 0;
}

static int nrfs1_access(const char *path, int mask)
{
	printf("nrfs1_access\n");
	request_t *req = build_req(RAID1, cmd_access, path, NULL, 0, 0, 0);
	req->f_info.mask = mask;
	req->sendback = true;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	writen(sfd0, req, sizeof(request_t));

	req->sendback = false;
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
	free(socket_fds);
}


static int nrfs1_utimens(const char* path, const struct timespec ts[2]) {
	printf("nrfs1_utimens\n");
	request_t *req = build_req(RAID1, cmd_utimens, path, NULL, 0, 0, 0);
	req->sendback = true;
	req->f_info.mask = AT_SYMLINK_NOFOLLOW;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	writen(sfd0, req, sizeof(request_t));
	writen(sfd0, ts, 2*sizeof(struct timespec));

	req->sendback = false;
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

	request_t *req = build_req(RAID1, cmd_rename, from, NULL, 0, 0, 0);
	// req->sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	size_t len = strlen(to);

	writen(sfd0, req, sizeof(request_t));
	writen(sfd0, &len, sizeof(size_t));
	writen(sfd0, to, len);

	// req->sendback = false;
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
    .access      = nrfs1_access,
    .readdir     = nrfs1_readdir,
    .mkdir       = nrfs1_mkdir,
    .unlink      = nrfs1_unlink,
    .rmdir       = nrfs1_rmdir,
    .rename      = nrfs1_rename,
    .truncate    = nrfs1_truncate,
    .utimens     = nrfs1_utimens,
    .create      = nrfs1_create,
    .open        = nrfs1_open,
    .read        = nrfs1_read,
    .write       = nrfs1_write,
    .release     = nrfs1_release,
    .opendir     = nrfs1_opendir,
    .releasedir  = nrfs1_releasedir,
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

	init_storage(argv[1], argv[2], &strg);
	// test_storage(&strg);
	init(&strg);

	int len = 32;
	char buff0[len];
	char buff1[len];
	char *buff2 = "-f";
	char *buff3 = "-s";

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

	umask(0);
	int fuse_res = fuse_main(argc, fuse_argv, nrfs_oper, NULL);

	cleanup();
	printf("EXIT BOIIIIIIII\n");
	return fuse_res;
	
}