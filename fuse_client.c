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
#include <sys/epoll.h>
#include "utils.h"
#include "info.h"
#include "parse.h"
#include "tst.h"


#define MAX_EVENTS 10

struct epoll_event ev, events[MAX_EVENTS];
int epoll_fd, nfds, nclients;

void init(strg_info_t *strg);
int init_connection(strg_info_t *strg);
char *get_time();
void init_hotswap();


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
bool reconnect_requested = false;
pthread_mutex_t reconnect_lock;


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

int get_err(int res0, int res1) {
	if (server_isalive(RAID1_MAIN))
		return -res0;
	else return -res1;
}

void log_msg(FILE *f, char *msg) {
	fprintf(f, "%s\n", msg);
	fflush(f);
}

void log_server_info(FILE *f, strg_info_t *strg, remote *server) {
	char *cur_time = get_time();
	fprintf(f, "%s %s %s:%s ", cur_time, strg->strg.diskname,
								 server->ip_address, server->port);
	free(cur_time);
	fflush(f);
}

void *reconnect(void *data) {
	log_server_info(log_file, &strg, &strg.strg.servers[dead_server]);
	log_msg(log_file, MSG_RECONNECT);
	close(socket_fds[dead_server]);
	clock_t begin;
	clock_t time_spent;
 	/* Mark beginning time */
	begin = clock();
	while (true) {
		int res = init_server(&socket_fds[dead_server], &strg.strg.servers[dead_server]);
		if (res == 0) {
			// printf("\n\n !!RECONNECTED SUCCESFULLY!! \n\n\n");
			log_server_info(log_file, &strg, &strg.strg.servers[dead_server]);
			log_msg(log_file, MSG_RECONNECT_SUCCESS);
			reconnect_requested = false;
			dead_server = -1;
			break;
		}
		/* Get CPU time since loop started */
		time_spent = (clock_t)(clock() - begin) / CLOCKS_PER_SEC;

		if (time_spent >= strg.timeout){
			log_server_info(log_file, &strg, &strg.strg.servers[dead_server]);
			log_msg(log_file, MSG_RECONNECT_FAIL);
			log_server_info(log_file, &strg, &strg.strg.servers[dead_server]);
			log_msg(log_file, MSG_SERVER_LOST);

			init_hotswap();
			break;
		}
	}
	// uncomment this if you want to try reconnecting after every command
	// otherwise it'll try only once
	// reconnect_requested = false;
	return NULL;
}

 void try_reconnect(int nth_server) {	
	pthread_mutex_lock(&reconnect_lock);
 	if (!reconnect_requested) {
 		reconnect_requested = true;
 		dead_server = nth_server;
		pthread_mutex_unlock(&reconnect_lock);
		pthread_t t;
		pthread_create(&t, NULL, reconnect, NULL);
	}
	pthread_mutex_unlock(&reconnect_lock);
}


/** initialize connection to servers */
int init_connection(strg_info_t *strg) {
	socket_fds = malloc(strg->strg.server_count*sizeof(int));
	int i;
	for (i = 0; i < strg->strg.server_count; ++i) {
		int res = init_server(&socket_fds[i], &strg->strg.servers[i]);
		log_server_info(log_file, strg, &strg->strg.servers[i]);
		if (res == 0) {
			log_msg(log_file, "open connection");
		} else {
			dead_server = i;
			log_msg(log_file, MSG_RECONNECT_FAIL);
		}
	}
	return 0;
}

void init_hotswap() {
	int res;
	log_server_info(log_file, &strg, &strg.strg.hotswap);
	log_msg(log_file, MSG_HOTSWAP_INIT);
	res = init_server(&socket_fds[dead_server], &strg.strg.hotswap);
	if (res == 0) {
		int worker = get_working_server();
		int sfd = socket_fds[worker];
		request_t req;
		build_req(&req, RAID1, cmd_restore_dir, NULL, NULL, 0, 0, 0);
		req.f_info.mode = send_to_server;
		writen(sfd, &req, sizeof(request_t));
		writen(sfd, &strg.strg.hotswap, sizeof(remote));

		status st;
		readn(sfd, &st, sizeof(status));

		log_server_info(log_file, &strg, &strg.strg.hotswap);
		log_msg(log_file, MSG_HOTSWAP_ADD);
		remote tmp;
		memcpy(&tmp, &strg.strg.servers[dead_server], sizeof(remote));
		memcpy(&strg.strg.servers[dead_server], &strg.strg.hotswap, sizeof(remote));
		memcpy(&strg.strg.hotswap, &tmp, sizeof(remote));
		dead_server = -1;
	} else {
		log_server_info(log_file, &strg, &strg.strg.hotswap);
		log_msg(log_file, MSG_HOTSWAP_FAILED);
	}
	// this is important to be able to reconnect after hot swap
	reconnect_requested = false;
}


void init(strg_info_t *strg) {
	md5_attr = NULL;
	writing_file = NULL;
	dead_server = -1;
	epoll_fd = epoll_create1(0);
	pthread_mutex_init(&reconnect_lock, NULL);
	log_file = fopen(strg->errorlog, "a");
	if (log_file == NULL) {
		// exit(-1);
	}
	init_connection(strg);
}


static int nrfs1_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi) {

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

		if (read_b == -1) {
			try_reconnect(RAID1_MAIN);
		}

		char *tok;
		tok = strtok(resp.buff, ",");
	
		while(tok != NULL) {
			filler(buf, tok, NULL, 0);
			tok = strtok(NULL, ",");
		}
	}
	return 0;
}



status send_file(int nth_server, request_t *req, const char *buf, int *err) {

	// send request to server
	int sfd = socket_fds[nth_server];
	int res;
	status st;
	res = writen(sfd, req, sizeof(request_t));
	if (res == -1) {
		try_reconnect(nth_server);
		st = server_dead;
	}
	
	if (req->sendback) {
		// read file open status from server
		res = readn(sfd, &st, sizeof(status));
		if (res == -1) {
			try_reconnect(nth_server);
			st = server_dead;
		}
	}
	
	if (req->sendback && st == error) {
		res = readn(sfd, err, sizeof(int));
		if (res == -1) {
			try_reconnect(nth_server);
			st = server_dead;
		}
		
		return st;
	} else {

		res = writen(sfd, buf, req->f_info.f_size);
		if (res == -1) {
			try_reconnect(nth_server);
			st = server_dead;
		}

		if (req->sendback) {
			res = readn(sfd, &st, sizeof(status));
			if (res == -1) {
				try_reconnect(nth_server);
				st = server_dead;
			}
			
			if (st == error) {
				res = readn(sfd, err, sizeof(int));
				if (res == -1) {
					try_reconnect(nth_server);
					st = server_dead;
				}
				return st;
			}
		}
	}

	return st;
}

static int nrfs1_write(const char *path, const char *buf, size_t size, off_t offset,
														struct fuse_file_info *fi) {
	request_t req;
	build_req(&req, RAID1, cmd_write, path, fi, size, offset, 0);
	req.f_info.flags |= O_WRONLY;
	req.sendback = true;
	
	
	if (writing_file == NULL) {
		writing_file = malloc(NAME_LEN);
		strcpy(writing_file, path);
	}
	
	int err;
	status st = dummy;

	if (server_isalive(RAID1_MAIN)) {
		st = send_file(RAID1_MAIN, &req, buf, &err);
		if (st == error) {
			return -err;
		}
	} 

	if (server_isalive(RAID1_REPLICANT)) {
		st = send_file(RAID1_REPLICANT, &req, buf, &err);
		if (st == error) {
			return -err;
		}
	}

	return size;
}


void restore_file(request_t *restore_req, int nth_server) {
	int sfd = socket_fds[nth_server];
	restore_req->sendback = false;
	writen(sfd, restore_req, sizeof(request_t));
	writen(sfd, &strg.strg.servers[1-nth_server], sizeof(remote));
	status st;
	readn(sfd, &st, sizeof(status));

}


static int nrfs1_open(const char *path, struct fuse_file_info *fi) {

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

		readn(sfd0, &md5_0, sizeof(md5_t));
		readn(sfd1, &md5_1, sizeof(md5_t));

		readn(sfd0, &f_size0, sizeof(off_t));
		readn(sfd1, &f_size1, sizeof(off_t));

		request_t restore_req;
		build_req(&restore_req, RAID1, cmd_restore_file, path, NULL, 0, 0, 0);


		if (hash0_match != hash_match && hash1_match != hash_match) {
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
			fprintf(log_file, "%s -- %s is corrupt\n", MSG_STORAGE_ERROR, path);
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
			fprintf(log_file, "%s -- %s is corrupt\n", MSG_STORAGE_ERROR, path);
		} else if (hash0_match == hash_match && hash1_match == hash_mismatch) {
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
			log_msg(log_file, "sending file");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
			fprintf(log_file, "%s file restored\n", path);
			fflush(log_file);
			restore_file(&restore_req, RAID1_MAIN);
		} else if (hash0_match == hash_mismatch && hash1_match == hash_match) {			
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
			log_msg(log_file, "sending file");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
			fprintf(log_file, "%s file restored\n", path);
			fflush(log_file);
			restore_file(&restore_req, RAID1_REPLICANT);
		} else if (hash0_match == hash1_match && hash0_match == hash_match) {
			if (strcmp((const char*)md5_0.hash, (const char*)md5_1.hash) != 0) {
				if (f_size0 > f_size1) {
					log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
					log_msg(log_file, "sending file");
					log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
					fprintf(log_file, "%s file restored\n", path);
					fflush(log_file);
					restore_file(&restore_req, RAID1_MAIN);
				}
				else if (f_size0 < f_size1) {
					log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
					log_msg(log_file, "sending file");
					log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
					fprintf(log_file, "%s file restored\n", path);
					fflush(log_file);
					restore_file(&restore_req, RAID1_REPLICANT);
				}
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
			try_reconnect(nth_server);
			return error;
		}
		res = readn(sfd, &st, sizeof(status));
		if (res == -1) {
			try_reconnect(nth_server);
			return error;
		}

		if (st == error) {
			res = readn(sfd, err, sizeof(int));
			if (res == -1) {
				try_reconnect(nth_server);
				return error;
			}
		} else {
			res = readn(sfd, stbuf, sizeof(struct stat));
			if (res == -1) {
				try_reconnect(nth_server);
				return error;
			}
		}
	} 
	return st;
}




static int nrfs1_getattr(const char *path, struct stat *stbuf) {
	request_t req;
	build_req(&req, RAID1, cmd_getattr, path, NULL, 0, 0, 0);
	status st0 = error, st1 = error;

	int res0, res1;
	struct stat stbuf0, stbuf1;
	

	if (server_isalive(RAID1_MAIN)) {
		st0 = nrfs1_getattr_helper(RAID1_MAIN, &req, &stbuf0, &res0);
	}
	if (server_isalive(RAID1_REPLICANT)) {
		st1 = nrfs1_getattr_helper(RAID1_REPLICANT, &req, &stbuf1, &res1);
	}


	if (st0 == error && st1 == error) {
		return get_err(res0, res1);
	} else {
		if (st0 != error) {
			memcpy(stbuf, &stbuf0, sizeof(struct stat));
		} else if (st1 != error) {
			memcpy(stbuf, &stbuf1, sizeof(struct stat));
		}
	}
	
	return 0;
}

static void* nrfs1_init(struct fuse_conn_info *conn) {

	return NULL;
}

static void nrfs1_destroy(void* private_data) {
}

static int nrfs1_read(const char* path, char *buf, size_t size, off_t offset,
											 struct fuse_file_info* fi) {
	request_t req;
	build_req(&req, RAID1, cmd_read, path, fi, size, offset, 0);
	
	req.f_info.flags |= O_RDONLY;
	int sfd;
	if (server_isalive(RAID1_MAIN)) {
		sfd = socket_fds[RAID1_MAIN];
	} else if (server_isalive(RAID1_REPLICANT)) {
		sfd = socket_fds[RAID1_REPLICANT];
		try_reconnect(RAID1_MAIN);
	}

	size_t sent = 0;
	size_t read_n = 0;
	sent = writen(sfd, &req, sizeof(request_t));
	if (sent == -1) {
		try_reconnect(RAID1_MAIN);
	}
	status st;
	read_n = readn(sfd, &st, sizeof(status));
	if (read_n == -1) {
		try_reconnect(RAID1_MAIN);
	}
	
	if (st == error) {
		int res;
		readn(sfd, &res, sizeof(res));
		if (read_n == -1) {
			try_reconnect(RAID1_MAIN);
		}
		return -res;
		
	} else {
		
		// file chunk size about to receive
		size_t toRec = 0;
		read_n = readn(sfd, &toRec, sizeof(size_t));
		if (read_n == -1) {
			try_reconnect(RAID1_MAIN);
		}
		read_n = readn(sfd, buf, toRec);
		if (read_n == -1) {
			try_reconnect(RAID1_MAIN);
		}
	}

	if (read_n <= 0) return 0;
	else return read_n;
}

static int nrfs1_release(const char* path, struct fuse_file_info *fi) {
	if (writing_file != NULL && strcmp(writing_file, path)== 0) {
		request_t req;
		build_req(&req, RAID1, cmd_release, path, NULL, 0, 0, 0);
		req.sendback = false;
		int sfd0 = socket_fds[RAID1_MAIN];
		int sfd1 = socket_fds[RAID1_REPLICANT];

		size_t res;

		if (server_isalive(RAID1_MAIN)) {
			res = writen(sfd0, &req ,sizeof(request_t));
			if (res == -1) {
				try_reconnect(RAID1_MAIN);
			}
		}

		if (server_isalive(RAID1_REPLICANT)) {
			writen(sfd1, &req, sizeof(request_t));
			res = writen(sfd0, &req ,sizeof(request_t));
			if (res == -1) {
				try_reconnect(RAID1_MAIN);
			}
		}


		free(writing_file);
		writing_file = NULL;
	} 
	
	return 0;
}


static int nrfs1_unlink(const char* path) {
	request_t req;
	build_req(&req, RAID1, cmd_unlink, path, NULL, 0, 0, 0);
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	int res0, res1;
	status st0, st1;

	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	st0 = response_handler(RAID1_MAIN, &res0);


	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st1 = response_handler(RAID1_REPLICANT, &res1);

	if (st0 == error && st1 == error) 
		return get_err(res0, res1);

	return 0;
}

static int nrfs1_rmdir(const char* path) {
	request_t req;
	build_req(&req, RAID1, cmd_rmdir, path, NULL, 0, 0, 0);
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	int res0, res1;
	status st0, st1;

	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	st0 = response_handler(RAID1_MAIN, &res0);

	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st1 = response_handler(RAID1_REPLICANT, &res1);

	if (st0 == error && st1 == error) 
		return get_err(res0, res1);
		

	return 0;
}


static int nrfs1_mkdir(const char* path, mode_t mode) {
	request_t req;
	build_req(&req, RAID1, cmd_mkdir, path, NULL, 0, 0, 0);
	req.f_info.mode = mode;
	req.sendback = true;
	// printf("mode -- %d\n", mode);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	int res0, res1;
	status st0, st1;

	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	st0 = response_handler(RAID1_MAIN, &res0);


	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st1 = response_handler(RAID1_REPLICANT, &res1);

	if (st0 == error && st1 == error) 
		return get_err(res0, res1);

	return 0;
}

static int nrfs1_opendir(const char* path, struct fuse_file_info* fi) {

	return 0;
}

static int nrfs1_releasedir(const char* path, struct fuse_file_info *fi) {

	return 0;
}



static int nrfs1_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	request_t req;
	build_req(&req, RAID1, cmd_create, path, fi, 0, 0, 0);
	req.f_info.mode = mode;
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	status st0, st1;
	int res0, res1;

	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	st0 = response_handler(RAID1_MAIN, &res0);

	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st1 = response_handler(RAID1_REPLICANT, &res1);

	if (st0 == error && st1 == error) 
		return get_err(res0, res1);

	return 0;
}

static int nrfs1_truncate(const char *path, off_t size) {
	
	return 0;
}

static int nrfs1_access(const char *path, int mask)
{
	request_t req;
	build_req(&req, RAID1, cmd_access, path, NULL, 0, 0, 0);
	req.f_info.mask = mask;
	req.sendback = true;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	int res0, res1;
	status st0, st1;

	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	st0 = response_handler(RAID1_MAIN, &res0);


	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	st1 = response_handler(RAID1_REPLICANT, &res1);
	
	if (st0 == error && st1 == error) 
		return get_err(res0, res1);

	return 0;
}


void cleanup() {
	fclose(log_file);
	free(socket_fds);
	pthread_mutex_destroy(&reconnect_lock);
}


static int nrfs1_utimens(const char* path, const struct timespec ts[2]) {
	request_t req;
	build_req(&req, RAID1, cmd_utimens, path, NULL, 0, 0, 0);
	req.sendback = true;
	req.f_info.mask = AT_SYMLINK_NOFOLLOW;

	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	int res0, res1;
	status st0, st1;

	if (server_isalive(RAID1_MAIN)) {
		writen(sfd0, &req, sizeof(request_t));
		writen(sfd0, ts, 2*sizeof(struct timespec));
	}

	st0 = response_handler(RAID1_MAIN, &res0);


	if (server_isalive(RAID1_REPLICANT)){
		writen(sfd1, &req, sizeof(request_t));
		writen(sfd1, ts, 2*sizeof(struct timespec));
	}

	st1 = response_handler(RAID1_REPLICANT, &res1);

	if (st0 == error && st1 == error) 
		return get_err(res0, res1);

	return 0;
}

static int nrfs1_rename(const char *from, const char *to) {
	request_t req;
	build_req(&req, RAID1, cmd_rename, from, NULL, 0, 0, 0);
	req.sendback = true;
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	int res0, res1;
	status st0, st1;

	size_t len = strlen(to);

	if (server_isalive(RAID1_MAIN)) {
		writen(sfd0, &req, sizeof(request_t));
		writen(sfd0, &len, sizeof(size_t));
		writen(sfd0, to, len);
	}

	st0 = response_handler(RAID1_MAIN, &res0);

	if (server_isalive(RAID1_REPLICANT)) {
		writen(sfd1, &req, sizeof(request_t));
		writen(sfd1, &len, sizeof(size_t));
		writen(sfd1, to, len);
	}

	st1 = response_handler(RAID1_REPLICANT, &res1);

	if (st0 == error && st1 == error) 
		return get_err(res0, res1);

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

	argc = 3;
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
	return fuse_res;
	
}