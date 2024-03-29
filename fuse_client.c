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
#include <sys/epoll.h>
#include <sys/mman.h>
#include "utils.h"
#include "info.h"
#include "parse.h"
#include "tst.h"

#define MAX_EVENTS 10

struct epoll_event ev, events[MAX_EVENTS];
int epoll_fd, nfds;

void init(strg_info_t *strg);
int init_connection(strg_info_t *strg);
char *get_time();
void init_hotswap();
void try_reconnect(int nth_server);


int *socket_fds;		// soccket file decriptors
strg_info_t strg;		// global storage info
FILE *log_file;			// log file_chun
int dead_server;		// index of dead server
char *writing_file;		// name of file that's being written
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
		int read_b = readn(sfd, &st, sizeof(status));
		if (read_b == -1) {
			printf("\n\n CONNECTION LOST IN response_handler\n\n\n");
			try_reconnect(nth_server);
		}
		if (st == error) {
			read_b = readn(sfd, err, sizeof(int));
			if (read_b == -1) {
				printf("\n\n CONNECTION LOST IN response_handler\n\n\n");
				try_reconnect(nth_server);
			}
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
		printf("In try_reconnect\n");
		pthread_t t;
		pthread_create(&t, NULL, reconnect, NULL);
	}
	pthread_mutex_unlock(&reconnect_lock);
}


/** initialize connection to servers */
int init_connection(strg_info_t *strg) {
	printf("IN client main\n");
	socket_fds = malloc(strg->strg.server_count*sizeof(int));
	int i;
	for (i = 0; i < strg->strg.server_count; ++i) {
		int res = init_server(&socket_fds[i], &strg->strg.servers[i]);
		log_server_info(log_file, strg, &strg->strg.servers[i]);
		if (res == 0) {
			log_msg(log_file, "open connection");
			ev.data.fd = socket_fds[i];
			ev.events = EPOLLIN | EPOLLET;
			epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fds[i], &ev);
		} else {
			dead_server = i;
			log_msg(log_file, MSG_RECONNECT_FAIL);
		}
	}
	return 0;
}

void init_hotswap() {
	int res;
	printf("\n\n !!! INITIALIZING HOTSWAP !!! \n\n\n");
	log_server_info(log_file, &strg, &strg.strg.hotswap);
	log_msg(log_file, MSG_HOTSWAP_INIT);
	res = init_server(&socket_fds[dead_server], &strg.strg.hotswap);

	if (res == 0) {
		int worker = get_working_server();
		int sfd = socket_fds[worker];
		request_t req;
		build_req(&req, RAID1, cmd_restore_dir, NULL, NULL, 0, 0, 0);
		req.f_info.mode = send_to_server;
		printf("\n\n\n !!RESTORE DIR!!!\n\n\n");
		writen(sfd, &req, sizeof(request_t));
		writen(sfd, &strg.strg.hotswap, sizeof(remote));

		status st;
		readn(sfd, &st, sizeof(status));
		printf("\n\n\n !!RESTORE DIR DONE!!!\n\n\n");

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
	// this is important to be able to reconnect after hot
	reconnect_requested = false;
}


void init(strg_info_t *strg) {
	writing_file = NULL;
	dead_server = -1;
	epoll_fd = epoll_create1(0);
	pthread_mutex_init(&reconnect_lock, NULL);
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

	request_t req;
	response_t resp0;
	response_t resp1;

	build_req(&req, RAID1, cmd_readdir, path, fi, 0, 0, 0);
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];


	if (server_isalive(RAID1_MAIN))
		writen(sfd0, &req, sizeof(request_t));

	if (server_isalive(RAID1_REPLICANT))
		writen(sfd1, &req, sizeof(request_t));

	int read_b;

	status st0, st1;
	int res0, res1;
	st0 = response_handler(RAID1_MAIN, &res0);
	st1 = response_handler(RAID1_REPLICANT, &res1);

	int entry_count0 = 0, entry_count1 = 0;

	if (st0 == error && st1 == error) {
		return get_err(res0, res1);
	}

	if (st0 != error && server_isalive(RAID1_MAIN)) {
		read_b = readn(sfd0, &entry_count0, sizeof(int));
		if (read_b == -1) {
			printf("SERVER DEAD IN READDIR\n");
			try_reconnect(RAID1_MAIN);
		}
		read_b = readn(sfd0, &resp0.packet_size, sizeof(resp0.packet_size));
		if (read_b == -1) {
			printf("SERVER DEAD IN READDIR\n");
			try_reconnect(RAID1_MAIN);
		}
		memset(resp0.buff, 0, sizeof(resp0.buff));
		read_b = readn(sfd0, resp0.buff, resp0.packet_size);
		if (read_b == -1) {
			printf("SERVER DEAD IN READDIR\n");
			try_reconnect(RAID1_MAIN);
		}
	}

	if (st1 != error && server_isalive(RAID1_REPLICANT)) {
		read_b = readn(sfd1, &entry_count1, sizeof(int));
		if (read_b == -1) {
			printf("SERVER DEAD IN READDIR\n");
			try_reconnect(RAID1_REPLICANT);
		}
		
		read_b = readn(sfd1, &resp1.packet_size, sizeof(resp1.packet_size));
		if (read_b == -1) {
			printf("SERVER DEAD IN READDIR\n");
			try_reconnect(RAID1_REPLICANT);
		}
		memset(resp1.buff, 0, sizeof(resp1.buff));
		read_b = readn(sfd1, resp1.buff, resp1.packet_size);
		if (read_b == -1) {
			printf("SERVER DEAD IN READDIR\n");
			try_reconnect(RAID1_MAIN);
		}
	}

	response_t *read_from = NULL;

	if (entry_count0 >= entry_count1)
		read_from = &resp0;
	else read_from = &resp1;

	char *tok;
	tok = strtok(read_from->buff, ",");
	
	while(tok != NULL) {
		filler(buf, tok, NULL, 0);
		// printf("tok -- %s\n", tok);
		tok = strtok(NULL, ",");
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
		printf("\n\n CONNECTION LOST!!! __ IN SEND_FILE\n\n\n");
		try_reconnect(nth_server);
		st = server_dead;
	}
	
	if (req->sendback) {
		// read file open status from server
		res = readn(sfd, &st, sizeof(status));
		if (res == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN SEND_FILE\n\n\n");
			try_reconnect(nth_server);
			st = server_dead;
		}
		printf("read -- %d\n", res);
	}
	
	if (req->sendback && st == error) {
	
		res = readn(sfd, err, sizeof(int));
		if (res == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN SEND_FILE\n\n\n");
			try_reconnect(nth_server);
			st = server_dead;
		}
	
		return st;
	} else {

		res = writen(sfd, buf, req->f_info.f_size);
		if (res == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN SEND_FILE\n\n\n");
			try_reconnect(nth_server);
			st = server_dead;
		}

		if (req->sendback) {
			res = readn(sfd, &st, sizeof(status));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN SEND_FILE\n\n\n");
				try_reconnect(nth_server);
				st = server_dead;
			}
			printf("read -- %d\n", res);
			if (st == error) {
				res = readn(sfd, err, sizeof(int));
				if (res == -1) {
					printf("\n\n CONNECTION LOST!!! __ IN SEND_FILE\n\n\n");
					try_reconnect(nth_server);
					st = server_dead;
				}
				printf("read -- %d\n", res);
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

	// init_hotswap();

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
	// printf("from -- %d\n", nth_server);
	restore_req->sendback = false;
	// printf("addr -- %s\n", strg.strg.servers[1-nth_server].ip_address);
	// printf("port -- %s\n", strg.strg.servers[1-nth_server].port);
	writen(sfd, restore_req, sizeof(request_t));
	writen(sfd, &strg.strg.servers[1-nth_server], sizeof(remote));
	status st;
	readn(sfd, &st, sizeof(status));

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


		if (hash0_match != hash_match && hash1_match != hash_match) {
			printf("something bad happened -- both hashes mismatched\n");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
			fprintf(log_file, "%s -- %s is corrupt\n", MSG_STORAGE_ERROR, path);
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
			fprintf(log_file, "%s -- %s is corrupt\n", MSG_STORAGE_ERROR, path);
		} else if (hash0_match == hash_match && hash1_match == hash_mismatch) {
			printf("hash0 matched but hash1 did not\n");
			printf("should copy from server0 to server1\n");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
			log_msg(log_file, "sending file");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
			fprintf(log_file, "%s file restored\n", path);
			fflush(log_file);
			restore_file(&restore_req, RAID1_MAIN);
		} else if (hash0_match == hash_mismatch && hash1_match == hash_match) {
			printf("hash1 matched but hash0 did not\n");
			printf("should copy from server1 to server0\n");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_REPLICANT]);
			log_msg(log_file, "sending file");
			log_server_info(log_file, &strg, &strg.strg.servers[RAID1_MAIN]);
			fprintf(log_file, "%s file restored\n", path);
			fflush(log_file);
			restore_file(&restore_req, RAID1_REPLICANT);
		} else if (hash0_match == hash1_match && hash0_match == hash_match) {
			printf("both hashes matched, now comparing each\n");
			if (strcmp((const char*)md5_0.hash, (const char*)md5_1.hash) != 0) {
				// printf("should copy from server0 to server1\n");
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
			printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
			try_reconnect(nth_server);
			return error;
		}
		res = readn(sfd, &st, sizeof(status));
		if (res == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
			try_reconnect(nth_server);
			return error;
		}

		if (st == error) {
			printf("STATUS -- %d\n", st);
			res = readn(sfd, err, sizeof(int));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
				try_reconnect(nth_server);
				return error;
			}
		} else {
			res = readn(sfd, stbuf, sizeof(struct stat));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN GETATTR_HELPER\n\n\n");
				try_reconnect(nth_server);
				return error;
			}
		}
	} 
	return st;
}




static int nrfs1_getattr(const char *path, struct stat *stbuf) {
	printf("nrfs1_getattr\n");
	printf("path -- %s\n", path);

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
		printf("no attr present\n");
	} else {
		if (st0 != error) {
			memcpy(stbuf, &stbuf0, sizeof(struct stat));
		} else if (st1 != error) {
			memcpy(stbuf, &stbuf1, sizeof(struct stat));
		}
	}

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
		sfd = socket_fds[RAID1_MAIN];
	} else if (server_isalive(RAID1_REPLICANT)) {
		sfd = socket_fds[RAID1_REPLICANT];
		try_reconnect(RAID1_MAIN);
	}

	size_t sent = 0;
	size_t read_n = 0;
	sent = writen(sfd, &req, sizeof(request_t));
	if (sent == -1) {
		printf("\n\n CONNECTION LOST!!! __ IN READ\n\n\n");
		try_reconnect(RAID1_MAIN);
	}
	printf("request sent\n");
	status st;
	read_n = readn(sfd, &st, sizeof(status));
	if (read_n == -1) {
		printf("\n\n CONNECTION LOST!!! __ IN READ\n\n\n");
		try_reconnect(RAID1_MAIN);
	}
	printf("status -- %d\n", st);
	printf("offset -- %lu\n", offset);
	printf("shouldve read -- %zu\n", size);

	if (st == error) {
		int res;
		readn(sfd, &res, sizeof(res));
		if (read_n == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN READ\n\n\n");
			try_reconnect(RAID1_MAIN);
		}
		printf("error -- %d\n", -res);
		return -res;
		
	} else {
		
		printf("about to read file\n");
		// file chunk size about to receive
		size_t toRec = 0;
		read_n = readn(sfd, &toRec, sizeof(size_t));
		if (read_n == -1) {
			printf("\n\n CONNECTION LOST!!! __ IN READ AFTER TOREC\n\n\n");
			try_reconnect(RAID1_MAIN);
		}
		read_n = readn(sfd, buf, toRec);
		if (read_n == -1) {
			printf("\n\n CONNECTION LOST!!! __ AFTER FILE REC\n\n\n");
			try_reconnect(RAID1_MAIN);
		}
		printf("read -- %zu\n", read_n);
	}

	printf("\n !!! READ DONE !!!\n\n");

	if (read_n <= 0) return 0;
	else return read_n;
}

static int nrfs1_release(const char* path, struct fuse_file_info *fi) {
	printf("nrfs1_release\n");
	printf("path -- %s\n", path);
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
				try_reconnect(RAID1_MAIN);
			}
		}

		if (server_isalive(RAID1_REPLICANT)) {
			writen(sfd1, &req, sizeof(request_t));
			res = writen(sfd0, &req ,sizeof(request_t));
			if (res == -1) {
				printf("\n\n CONNECTION LOST!!! __ IN RELASE\n\n\n");
				try_reconnect(RAID1_MAIN);
			}
		}


		free(writing_file);
		writing_file = NULL;
	} 
	
	return 0;
}


static int nrfs1_unlink(const char* path) {
	printf("nrfs1_unlink\n");

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
	printf("nrfs1_rmdir\n");

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
	printf("nrfs1_mkdir\n");

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
	printf("nrfs1_truncate\n");

	request_t req;
	build_req(&req, RAID1, cmd_truncate, path, NULL, 0, 0, 0);
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

static int nrfs1_access(const char *path, int mask)
{
	printf("nrfs1_access\n");
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
	close(epoll_fd);
	pthread_mutex_destroy(&reconnect_lock);
}


static int nrfs1_utimens(const char* path, const struct timespec ts[2]) {
	printf("nrfs1_utimens\n");
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
	printf("nrfs1_rename\n");

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


static struct fuse_operations nrfs5_oper = {};




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