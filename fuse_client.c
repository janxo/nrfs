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
int swap_file_fd = -1;
bool file_created = false;

// needed for fuse functions
// for local functions strg arg is explicitly passed
strg_info_t *strg_global;

void print_md5_sum(md5_t *md) {
	int i;
	for(i=0; i <MD5_DIGEST_LENGTH; i++) {
		printf("%02x",md->hash[i]);
 	}
}

static void get_file_hash(int fd, size_t f_size, md5_t *md5) {
	printf("\nABOUT TO CALCULATE HASH\n\n");
	char *file_buffer;

	file_buffer = mmap(0, f_size, PROT_READ, MAP_SHARED, fd, 0);
	MD5((unsigned char*) file_buffer, f_size, md5->hash);
	munmap(file_buffer, f_size);
	print_md5_sum(md5);
	char buff[128];
	int i;
	for(i=0; i <MD5_DIGEST_LENGTH; i++) {
		sprintf(buff+i*2, "%02x",md5->hash[i]);
	}
	printf("\n\n");
	printf("\nmd5 is -- %s\n", buff);
	printf("len is -- %zu\n", strlen(buff));
	// printf("digest len -- %d\n", strlen());
	memcpy(md5->hash, buff, 2*MD5_DIGEST_LENGTH);
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
	printf("in client before write\n");
	int wrote = write(sfd, req, sizeof(request_t));

	printf("after write, written -- %d\n", wrote);
	int read_b = read(sfd, &resp.packet_size, sizeof(resp.packet_size));
	printf("read %d bytes\n", read_b);
	int left_to_read = resp.packet_size - sizeof(resp.packet_size);
	printf("about to read -- %d bytes\n", left_to_read);
	read_b = readn(sfd, &resp.st, left_to_read);
	printf("received directories -- %s\n", resp.buff);
	// means server fd was closed
	if (read_b == 0) {
		printf("SERVER DEAD\n");
		// TODO
		// reconnect to server
		
	}
	printf("after read\n");
	printf("read %d bytes\n", read_b);
	printf("status is -- %d\n", resp.st);
	printf("buff -- %s\n", resp.buff);
	// filler(buf, resp.buff, NULL, 0);
	char *tok;
	tok = strtok(resp.buff, " ");

	
	while(tok != NULL) {
		filler(buf, tok, NULL, 0);
		printf("tok -- %s\n", tok);
		tok = strtok(NULL, " ");
	}

	if (resp.st == success) {
		printf("in success\n");
		log_msg(&strg, RAID1_MAIN, "readdir was successfull");
	}
	else if (resp.st < success)
		log_msg(&strg, RAID1_MAIN, "readdir -- something went wrong");

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




static status send_file(int sfd, int fd, request_t *req, cache_file_t *cach_file, size_t chunk_size) {

	struct stat stbuf;
	fstat(fd, &stbuf);
	printf("cache_size -- %zu\n", cach_file->f_size);
	printf("st_buf_size -- %zu\n", stbuf.st_size);
	printf("swap_fd -- %d\n", fd);
	assert(stbuf.st_size == cach_file->f_size);
	
	ssize_t numWritten = 0;
	size_t totWritten;


	req->f_info.offset = cach_file->offset;
	int counter = 0;
	for (totWritten = 0; totWritten < cach_file->f_size; ) {
		printf("\nIn writen count is -- %d\n\n", counter);
		counter++;
		size_t size = cach_file->f_size-totWritten;
		if (size > chunk_size) {
			size = chunk_size;
			req->st = writing;
		} else {
			req->st = done;
		}

		req->f_info.f_size = size;
		printf("req status -- %d\n", req->st);
		writen(sfd, req, sizeof(request_t));
		numWritten = sendfile(sfd, fd, NULL, size);
		printf("sent -- %zu\n", numWritten);
		
		if (numWritten <= 0) {
			if (numWritten == -1 && errno == EINTR)
				continue;
			else
				return error;
		}
		req->f_info.offset += numWritten;
		totWritten += numWritten;
	}
	return success;
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
	printf("fi flags -- %d\n", fi->flags);
	bool is_last_packet = false;

	if (cached_file.f_size == 0) {
		cached_file.offset = offset;
		swap_file_fd = open(SWAP_FILE, O_CREAT|O_RDWR|O_APPEND, 0644);
		write_req = build_req(RAID1, cmd_write, path, fi, writing, size, offset, 0);
		write_req->f_info.created = file_created;
		write_req->f_info.mode = cached_file.mode;
	}

	if (size != 0 && (size < FUSE_BUFF_LEN)) {
		is_last_packet = true;
		printf("size is -- %zu\n", size);
	} 

	pwrite(swap_file_fd, buf, size, offset);
	cached_file.f_size += size;

	if (is_last_packet) {
		int sfd0 = socket_fds[RAID1_MAIN];
		printf("should write file -- %zu\n", cached_file.f_size);
		get_file_hash(swap_file_fd, cached_file.f_size, &write_req->f_info.md5);
		// print_md5_sum(&write_req->f_info.hash);
		send_file(sfd0, swap_file_fd, write_req, &cached_file, FUSE_BUFF_LEN);

		status st = unused;
		readn(sfd0, &st, sizeof(status));

		printf("file write done with status -- %d\n", st);


		// reset file pointer to head
		lseek(swap_file_fd, SEEK_SET, 0);

		// successfull write to main server thus we write on replicant server
		if (st == done) {
			int sfd1 = socket_fds[RAID1_REPLICANT];
			send_file(sfd1, swap_file_fd, write_req, &cached_file, FUSE_BUFF_LEN);
		}

		// free resources
		free(write_req);
		write_req = NULL;
		free_cached(&cached_file);
		close(swap_file_fd);
		unlink(SWAP_FILE);
		file_created = false;
		printf("WRITE DONE\n");
	}


	return size;
}


static int nrfs1_open(const char *path, struct fuse_file_info *fi) {
	printf("nrfs1_open\n");
	if (fi == NULL) {
		printf("FI is NULL\n");
	}
	
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


	readn(sfd, stbuf, sizeof(struct stat));

	if (st == error) {
		printf("STATUS -- %d\n", st);
		
		int res;
		// printf("sizeof errno is -- %lu\n", sizeof(errno));
		readn(sfd, &res, sizeof(res));
		printf("errno -- %d\n", res);
		free(req);
		return -res;
	} 
	// printf("st_mode2 -- %d\n", stbuf->st_mode);
	// printf("sizeof stbuf -- %zu\n", sizeof(struct stat));
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
	// // char file_name[64];
	// // strcpy(file_name, "read");
	// log_msg(&strg, RAID1_MAIN, "read");
	// request_t req;
	// // response_t resp;
	// req.raid = RAID1;
	// req.fn = cmd_read;

	// build_req(&req, RAID1, cmd_readdir, path, 0, fi, 0);
	// int sfd = socket_fds[RAID1_MAIN];
	// write(sfd, &req, sizeof(req));

	return 0;
}

static int nrfs1_release(const char* path, struct fuse_file_info *fi) {
	printf("nrfs1_release\n");

	return 0;
}

static int nrfs1_rename(const char *from, const char *to) {
	printf("nrfs1_rename\n");

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

	file_created = true;
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
	unlink(SWAP_FILE);
}


static int nrfs1_utimens(const char* path, const struct timespec ts[2]) {
	printf("nrfs1_utimens\n");
	request_t *req = build_req(RAID1, cmd_utimens, path, NULL, unused, 0, 0, 0);
	req->f_info.mask = AT_SYMLINK_NOFOLLOW;
	// printf("no follow -- %d\n", AT_SYMLINK_NOFOLLOW);
	// printf("time0 --- %s\n", ctime(&(ts[0].tv_sec)));
	// printf("time1 --- %s\n", ctime(&(ts[1].tv_sec)));
	int sfd0 = socket_fds[RAID1_MAIN];
	int sfd1 = socket_fds[RAID1_REPLICANT];

	writen(sfd0, req, sizeof(request_t));
	write(sfd0, ts, 2*sizeof(struct timespec));

	writen(sfd1, req, sizeof(request_t));
	write(sfd1, ts, 2*sizeof(struct timespec));

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
	// char *buff3 = "-o";
	// char *buff4 = "nonempty";

	argc = 3;
	char *fuse_argv[argc];
	
	strcpy(buff0, argv[0]);
	strcpy(buff1, strg.strg.mountpoint);

	fuse_argv[0] = buff0;
	fuse_argv[1] = buff1;
	fuse_argv[2] = buff2;
	// fuse_argv[3] = buff3;
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