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
char *writing_file;


int get_working_server() {
	int working_server;
	if (dead_server == -1)
		working_server = RAID1_MAIN;
	else
		working_server = 1 - dead_server;
	return working_server;
}

static bool server_isalive(int server) {
	if (server == dead_server)
		return false;
	return true;
}

static status response_handler(int nth_server, int *err) {
	status st = dummy;
	if (server_isalive(nth_server)) {
		int sfd = socket_fds[nth_server];
		readn(sfd, &st, sizeof(status));
		if (st == error) {
			readn(sfd, err, sizeof(int));
			printf("error -- %d\n", -*err);
		}
	}
	return st;
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
	close(socket_fds[dead_server]);
	clock_t begin;
	clock_t time_spent;
 	/* Mark beginning time */
	begin = clock();
	while (true) {
		// printf("trying to reconnect\n");
		int res = init_server(&socket_fds[dead_server], &strg.strg.servers[dead_server]);
		if (res == 0) {
			dead_server = -1;
			printf("\n\n !!RECONNECTED SUCCESFULLY!! \n\n\n");
			break;
		}
		/* Get CPU time since loop started */
		time_spent = (clock_t)(clock() - begin) / CLOCKS_PER_SEC;
		if (time_spent >= strg.timeout){
			printf("couldn't reconnect\n");
			break;
		}
	}
	return NULL;
}

 void try_reconnect() {
	printf("In try_reconnect\n");
	pthread_t t;
	pthread_create(&t, NULL, reconnect, NULL);
	printf("\n\nRECONNECT DONE\n\n");
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
		} else dead_server = i;
	}
	return 0;
}
	


void init(strg_info_t *strg) {
	md5_attr = NULL;
	writing_file = NULL;
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
	request_t req;
	response_t resp;

	build_req(&req, RAID1, cmd_readdir, path, fi, 0, 0, 0);
	int sfd;

	if (server_isalive(RAID1_MAIN)) 
		sfd = socket_fds[RAID1_MAIN];
	else if (server_isalive(RAID1_REPLICANT))
		sfd = socket_fds[RAID1_REPLICANT];

	writen(sfd, &req, sizeof(request_t));

	status st;
	readn(sfd, &st, sizeof(status));
	if (st == error) {
		int res;
		readn(sfd, &res, sizeof(res));
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
	return 0;
}



status send_file(int sfd, request_t *req, const char *buf, md5_t *md5, int *err, size_t *sent) {

	// send request to server
	int r_sent = write(sfd, req, sizeof(request_t));
	int read_b;
	status st;
	printf("write request sent -- %d\n", r_sent);
	if (req->sendback) {
		// read file open status from server
		read_b = readn(sfd, &st, sizeof(status));
		if (read_b == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");

		}
		printf("read -- %d\n", read_b);
	}
	
	if (req->sendback && st == error) {
		printf("BEFORE READN\n");
		// read errno
		read_b = readn(sfd, err, sizeof(int));
		printf("read -- %d\n", read_b);
		printf("errno -- %d\n", *err);
		return st;
	} else {

		printf("should send -- %zu bytes\n", req->f_info.f_size);

		*sent = writen(sfd, buf, req->f_info.f_size);
		printf("sent -- %zu\n", *sent);

		if (req->sendback) {
			read_b = readn(sfd, &st, sizeof(status));
			printf("read -- %d\n", read_b);
			if (st == error) {
				read_b = readn(sfd, err, sizeof(int));
				printf("read -- %d\n", read_b);
				printf("error writing file -- %d\n", *err);
				return st;
			}
		}
	}

	return st;
}

static int nrfs1_write(const char *path, const char *buf, size_t size, off_t offset,
														struct fuse_file_info *fi) {
	printf("nrfs1_write\n");

	if (fi == NULL) {
		printf("FI is NULL\n");
	}


	request_t req;
	build_req(&req, RAID1, cmd_write, path, fi, size, offset, 0);
	req.f_info.flags |= O_WRONLY;
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	md5_t md5;
	

	// void *file_chunk = (void *) buf;
	// get_hash(file_chunk, req->f_info.f_size, &md5);

	if (writing_file == NULL) {
		writing_file = malloc(NAME_LEN);
		strcpy(writing_file, path);
	}

	// if (md5_attr == NULL) {
	// 	md5_attr = malloc(sizeof(md5_attr_t));
	// 	strcpy(md5_attr->name, path);
	// 	MD5_Init(&md5_attr->md5_cont);
	// }
	// assert(md5_attr != NULL);
	
	// MD5_Update(&md5_attr->md5_cont, buf, size);

	// printf("hash0 --- %s\n", md5.hash);
	// printf("hash1 --- %s\n", md5_1.hash);
	// int i;
	// for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", digest[i]);
 //   	printf("\n");
	size_t sent0, sent1;
	int err;
	status st = dummy;

	if (server_isalive(RAID1_MAIN)) {
		printf("server 0 is alive\n");
		st = send_file(sfd0, &req, buf, &md5, &err, &sent0);

		if (st == error) {
			return -err;
		}
	}

	if (server_isalive(RAID1_REPLICANT)) {
		printf("server1 is alive\n");
		st = send_file(sfd1, &req, buf, &md5, &err, &sent1);
		if (st == error) {
			return -err;
		}
	}
	if (server_isalive(RAID1_MAIN)) return sent0;
	if (server_isalive(RAID1_REPLICANT)) return sent1;
	return size;
}


void restore_file(request_t *restore_req, int nth_server) {
	// restore_req->f_info.mode = send_to_server;
	int sfd = socket_fds[nth_server];
	printf("from -- %d\n", nth_server);
	restore_req->sendback = false;
	printf("addr -- %s\n", strg.strg.servers[1-nth_server].ip_address);
	printf("port -- %s\n", strg.strg.servers[1-nth_server].port);
	writen(sfd, restore_req, sizeof(request_t));
	writen(sfd, &strg.strg.servers[1-nth_server], sizeof(remote));
}


static int nrfs1_open(const char *path, struct fuse_file_info *fi) {
	printf("nrfs1_open\n");
	printf("path -- %s\n", path);
	request_t req;
	build_req(&req, RAID1, cmd_open, path, fi, 0, 0, 0);

	if (dead_server == -1) {
		int sfd0 = socket_fds[RAID1_MAIN];
		int sfd1 = socket_fds[RAID1_REPLICANT];
		writen(sfd0, &req, sizeof(request_t));
		writen(sfd1, &req, sizeof(request_t));

		status hash0_match, hash1_match;
		md5_t md5_0, md5_1;
		off_t f_size0, f_size1;

		readn(sfd0, &hash0_match, sizeof(status));
		readn(sfd1, &hash1_match, sizeof(status));

		printf("hash0_match -- %d\n", hash0_match);
		printf("hash1_match -- %d\n", hash1_match);

		readn(sfd0, &md5_0, sizeof(md5_t));
		readn(sfd1, &md5_1, sizeof(md5_t));

		readn(sfd0, &f_size0, sizeof(off_t));
		readn(sfd1, &f_size1, sizeof(off_t));

		request_t restore_req;
		build_req(&restore_req, RAID1, cmd_restore_file, path, NULL, 0, 0, 0);		

		if (hash0_match != hash0_match && hash1_match != hash_match) {
			printf("something bad happened -- both hashes mismatched\n");
		} else if (hash0_match == hash_match && hash1_match == hash_mismatch) {
			printf("hash0 matched but hash1 did not\n");
			printf("should copy from server0 to server1\n");
			restore_file(&restore_req, RAID1_MAIN);
		} else if (hash0_match == hash_mismatch && hash1_match == hash_match) {
			printf("hash1 matched but hash0 did not\n");
			printf("should copy from server1 to server0\n");
			restore_file(&restore_req, RAID1_REPLICANT);
		} else if (hash0_match == hash1_match && hash0_match == hash_match) {
			printf("both hashes matched, now comparing each\n");
			if (strcmp((const char*)md5_0.hash, (const char*)md5_1.hash) != 0) {
				// printf("should copy from server0 to server1\n");
				if (f_size0 > f_size1)
					restore_file(&restore_req, RAID1_MAIN);
				else if (f_size0 < f_size1)
					restore_file(&restore_req, RAID1_REPLICANT);
			}
		}

	}
	return 0;
}


static status nrfs1_getattr_helper(int nth_server, request_t *req, struct stat *stbuf, int *err) {
	status st = dummy;
	if (server_isalive(nth_server)) {
		size_t res;
		int sfd = socket_fds[nth_server];
		res = writen(sfd, req, sizeof(request_t));
		if (res == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
			dead_server = RAID1_MAIN;
			return error;
		}
		res = readn(sfd, &st, sizeof(status));
		if (res == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
			dead_server = RAID1_MAIN;
			return error;
		}

		if (st == error) {
			printf("STATUS -- %d\n", st);
			res = readn(sfd, err, sizeof(int));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
				dead_server = RAID1_MAIN;
				return error;
			}
		} else {
			res = readn(sfd, stbuf, sizeof(struct stat));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
				dead_server = RAID1_MAIN;
				return error;
			}
		}
	} else {

	}
	return st;
}


// void print_stat(struct stat *stbuf, struct stat *stbuf1) {
// 	printf("dev_t -- %d -- %d\n", stbuf->st_dev, stbuf1->st_dev);
// 	printf("ino_t -- %d -- %d\n", stbuf->st_ino, stbuf1->st_ino);
// 	printf("mode_t -- %d -- %d\n", stbuf->st_mode, stbuf1->st_mode);
// 	printf("nlink_t -- %d -- %d\n", stbuf->st_nlink, stbuf1->st_nlink);
// 	printf("uid_t -- %d -- %d\n", stbuf->st_uid, stbuf1->st_uid);
// 	printf("gid_t -- %d -- %d\n", stbuf->st_gid, stbuf1->st_gid);
// 	printf("dev_t -- %d -- %d\n", stbuf->st_rdev, stbuf1->st_rdev);
// 	printf("off_t -- %d -- %d\n", stbuf->st_size, stbuf1->st_size);
// 	printf("blksize_t -- %d -- %d\n", stbuf->st_blksize, stbuf1->st_blksize);
// 	printf("blkcnt_t -- %d -- %d\n", stbuf->st_blocks, stbuf1->st_blocks);
// }
static int nrfs1_getattr(const char *path, struct stat *stbuf) {
	printf("nrfs1_getattr\n");
	printf("path -- %s\n", path);
	log_server_info(log_file, &strg, RAID1_MAIN);
	log_msg(log_file, "getattr");

	request_t req;
	build_req(&req, RAID1, cmd_getattr, path, NULL, 0, 0, 0);
	status st0 = error, st1 = error;

	int res0, res1;
	struct stat stbuf0, stbuf1;
	// int res1;
	// struct stat stbuf1;

	if (server_isalive(RAID1_MAIN)) {
		// nrfs1_getattr_helper(RAID1_REPLICANT, req, &stbuf1, &res1);
		st0 = nrfs1_getattr_helper(RAID1_MAIN, &req, &stbuf0, &res0);
		// if (st == error) return -EBADFD;
	}
	if (server_isalive(RAID1_REPLICANT)) {
		st1 = nrfs1_getattr_helper(RAID1_REPLICANT, &req, &stbuf1, &res1);
		// if (st == error) return -EBADFD;
	}


	// if (st == error) {
	// 	return -res;
	// }

	if (st0 == error && st1 == error) {
		if (server_isalive(RAID1_MAIN))
			return -res0;
		else return -res1;
		printf("no attr present\n");
	} else {
		if (st0 != error) {
			memcpy(stbuf, &stbuf0, sizeof(struct stat));
		} else if (st1 != error) {
			memcpy(stbuf, &stbuf1, sizeof(struct stat));
		}
	}
	// print_stat(stbuf, &stbuf1);

	printf("nrfs1_getattr DONE\n");
	
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
	request_t req;
	build_req(&req, RAID1, cmd_read, path, fi, size, offset, 0);
	
	req.f_info.flags |= O_RDONLY;
	int sfd;
	if (server_isalive(RAID1_MAIN)) {
		printf("IN READN RAID MAIN\n");
		sfd = socket_fds[RAID1_MAIN];
	}
	else if (server_isalive(RAID1_REPLICANT)) {
		printf("IN READN RAID REPLICANT\n");
		sfd = socket_fds[RAID1_REPLICANT];
	}
	size_t sent = 0;
	size_t read_n = 0;
	sent = writen(sfd, &req, sizeof(request_t));
	if (sent == -1) {
		printf("\n\n CONNECTION LOST!!! __ IN READ\n\n\n");
		// close(sfd);
		dead_server = RAID1_MAIN;
		// try_reconnect();
		// return -EAGAIN;
		if (server_isalive(RAID1_REPLICANT)) {
			sfd = socket_fds[RAID1_REPLICANT];
			sent = writen(sfd, &req, sizeof(request_t));
		}
	}
	printf("request sent\n");
	status st;
	read_n = readn(sfd, &st, sizeof(status));
	if (read_n == -1) {
		printf("\n\n CONNECTION LOST!!! __ IN READ\n\n\n");
		// close(sfd);
		dead_server = RAID1_MAIN;
		// try_reconnect();
		// return -EAGAIN;
		if (server_isalive(RAID1_REPLICANT)){
			sfd = socket_fds[RAID1_REPLICANT];
			writen(sfd, &req, sizeof(request_t));
			read_n = readn(sfd, &st, sizeof(status));
		}
	}
	printf("status -- %d\n", st);
	printf("offset -- %lu\n", offset);
	printf("shouldve read -- %zu\n", size);
	// TODO maybe try to read from second server
	// this time it just retunrs with errno
	if (st == error) {
		int res;
		readn(sfd, &res, sizeof(res));
		if (read_n == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN READ\n\n\n");
			// close(sfd);
			dead_server = RAID1_MAIN;
			// try_reconnect();
			// return -EAGAIN;
			if (server_isalive(RAID1_REPLICANT)) {
				sfd = socket_fds[RAID1_REPLICANT];
				writen(sfd, &req, sizeof(request_t));
				read_n = readn(sfd, &st, sizeof(status));
				readn(sfd, &res, sizeof(res));
			}
		}
		printf("error -- %d\n", -res);
		return -res;
		
	} else {
		
		printf("about to read file\n");
		size_t toRec = 0;
		read_n = readn(sfd, &toRec, sizeof(size_t));
		if (read_n == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN READ AFTER TOREC\n\n\n");
			// close(sfd);
			dead_server = RAID1_MAIN;
			// try_reconnect();
			// return -EAGAIN;
		}
		read_n = readn(sfd, buf, toRec);
		if (read_n == -1) {
			printf("\n\n CONNECTION LOST!!! __ AFTER FILE REC\n\n\n");
			// close(sfd);
			dead_server = RAID1_MAIN;
			// try_reconnect();
			// return -EAGAIN;
		}
		printf("read -- %zu\n", read_n);
		// if (read_n == -1) read_n = -errno;

		// free(tmp);
	}

	printf("\n !!! READ DONE !!!\n\n");
	return read_n;
}

static int nrfs1_release(const char* path, struct fuse_file_info *fi) {
	printf("nrfs1_release\n");
	printf("path -- %s\n", path);
	// md5_attr != NULL && strcmp(md5_attr->name, path)
	if (writing_file != NULL && strcmp(writing_file, path)== 0) {
		printf("sending hashes\n");
		request_t req;
		build_req(&req, RAID1, cmd_release, path, NULL, 0, 0, 0);
		req.sendback = false;
		int sfd0 = socket_fds[RAID1_MAIN];
		int sfd1 = socket_fds[RAID1_REPLICANT];

		size_t res;
		if (server_isalive(RAID1_MAIN)) {
			res = writen(sfd0, &req ,sizeof(request_t));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN RELASE\n\n\n");
				dead_server = RAID1_MAIN;
				return -EBADFD;
			}
		}

		if (server_isalive(RAID1_REPLICANT)) {
			writen(sfd1, &req, sizeof(request_t));
			res = writen(sfd0, &req ,sizeof(request_t));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN RELASE\n\n\n");
				dead_server = RAID1_MAIN;
				return -EBADFD;
			}
		}


		free(writing_file);
		writing_file = NULL;
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

	request_t req;
	build_req(&req, RAID1, cmd_unlink, path, NULL, 0, 0, 0);
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));


	int res;
	status st = response_handler(RAID1_MAIN, &res);
	// readn(sfd0, &st, sizeof(status));
	if (st == error) {
		// readn(sfd0, &res, sizeof(res));
		// printf("error -- %d\n", -res);
		return -res;
	}


	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st = response_handler(RAID1_REPLICANT, &res);
	if (st == error) {
		return -res;
	}

	return 0;
}

static int nrfs1_rmdir(const char* path) {
	printf("nrfs1_rmdir\n");

	request_t req;
	build_req(&req, RAID1, cmd_rmdir, path, NULL, 0, 0, 0);
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	int res;
	status st = response_handler(RAID1_MAIN, &res);
	if (st == error) {
		return -res;
	}

	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st = response_handler(RAID1_REPLICANT, &res);
	if (st == error) {
		return -res;
	}
	return 0;
}


static int nrfs1_mkdir(const char* path, mode_t mode) {
	printf("nrfs1_mkdir\n");

	request_t req;
	build_req(&req, RAID1, cmd_mkdir, path, NULL, 0, 0, 0);
	req.f_info.mode = mode;
	req.sendback = true;
	// printf("mode -- %d\n", mode);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	int res;
	status st = response_handler(RAID1_MAIN, &res);
	if (st == error) {
		return -res;
	}

	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st = response_handler(RAID1_REPLICANT, &res);
	if (st == error) {
		return -res;
	}

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
	request_t req;
	build_req(&req, RAID1, cmd_create, path, fi, 0, 0, 0);
	req.f_info.mode = mode;
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));


	status st, st1;
	int err, err1;
	st = response_handler(RAID1_MAIN, &err);
	if (st == error) {
		return -err;
	}
		// req->sendback = false;
	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st1 = response_handler(RAID1_REPLICANT, &err1);
	if (st1 == error) {
		return -err1;
	}

	return 0;
}

static int nrfs1_truncate(const char *path, off_t size) {
	printf("nrfs1_truncate\n");
	
	return 0;
}

static int nrfs1_access(const char *path, int mask)
{
	printf("nrfs1_access\n");
	request_t req;
	build_req(&req, RAID1, cmd_access, path, NULL, 0, 0, 0);
	req.f_info.mask = mask;
	req.sendback = true;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];
	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	int res;
	status st = response_handler(RAID1_MAIN, &res);

	if (st == error) {
		return -res;
	}


	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st = response_handler(RAID1_REPLICANT, &res);
	if (st == error) {
		return -res;
	}

	return 0;
}


void cleanup() {
	fclose(log_file);
	free(socket_fds);
}


static int nrfs1_utimens(const char* path, const struct timespec ts[2]) {
	printf("nrfs1_utimens\n");
	request_t req;
	build_req(&req, RAID1, cmd_utimens, path, NULL, 0, 0, 0);
	req.sendback = true;
	req.f_info.mask = AT_SYMLINK_NOFOLLOW;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	if (server_isalive(RAID1_MAIN)) {
		writen(sfd0, &req, sizeof(request_t));
		writen(sfd0, ts, 2*sizeof(struct timespec));
	}


	int res;
	status stat = response_handler(RAID1_MAIN, &res);

	if (stat == error) {
		return -res;
	}

	if (server_isalive(RAID1_REPLICANT)){
		writen(sfd1, &req, sizeof(request_t));
		writen(sfd1, ts, 2*sizeof(struct timespec));
	}

	stat = response_handler(RAID1_REPLICANT, &res);
	if (stat == error) {
		return -res;
	}

	return 0;
}

static int nrfs1_rename(const char *from, const char *to) {
	printf("nrfs1_rename\n");

	request_t req;
	build_req(&req, RAID1, cmd_rename, from, NULL, 0, 0, 0);
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	size_t len = strlen(to);

	if (server_isalive(RAID1_MAIN)) {
		writen(sfd0, &req, sizeof(request_t));
		writen(sfd0, &len, sizeof(size_t));
		writen(sfd0, to, len);
	}


	int res;
	status stat = response_handler(RAID1_MAIN, &res);

	if (stat == error) {
		return -res;
	}

	if (server_isalive(RAID1_REPLICANT)) {
		writen(sfd1, &req, sizeof(request_t));
		writen(sfd1, &len, sizeof(size_t));
		writen(sfd1, to, len);
	}

	stat = response_handler(RAID1_REPLICANT, &res);
	if (stat == error) {
		return -res;
	}

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
	char *buff2 = "-s";
	char *buff3 = "-f";

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