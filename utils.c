#include <unistd.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"


ssize_t readn(int fd, const void *buffer, size_t n) {
	// printf("!!! IN READN !!!\n");
	ssize_t numRead;
	size_t totRead;
	char *buf;

	buf = (char *) buffer;
	// printf("in readn before loop\n");
	for (totRead = 0; totRead < n; ) {
		// printf("in da loop");
		numRead = read(fd, buf, n - totRead);
		// printf("numRead -- %d\n", numRead);
		if (numRead == 0)
			return totRead;
		if (numRead == -1) {
		if (errno == EINTR)
			continue;
		else
			return -1;
		}
		totRead += numRead;
		buf += numRead;
		// printf("totread -- %d\n", totRead);
	}
	return totRead;

}



ssize_t writen(int fd, const void *buffer, size_t n) {
	// printf("!!! IN WRITEN !!!\n");
	ssize_t numWritten;
	size_t totWritten;
	char *buf;

	buf = (char *) buffer;
	for (totWritten = 0; totWritten < n; ) {
		numWritten = write(fd, buf, n - totWritten);
		
		if (numWritten <= 0) {
		if (numWritten == -1 && errno == EINTR)
			continue;
		else
			return -1;
		}
		totWritten += numWritten;
		buf += numWritten;
	}
	return totWritten;
}

status send_file(int sfd, request_t *req, const char *buf, md5_t *md5, int *err) {

	// send request to server
	write(sfd, req, sizeof(request_t));
	status st;

	if (req->sendback)
		// read file open status from server
		read(sfd, &st, sizeof(status));
	
	if (req->sendback && st == error) {
		printf("BEFORE READN\n");
		// read errno
		read(sfd, err, sizeof(int));
		printf("errno -- %d\n", *err);
		return st;
	} else {

		printf("should send -- %zu bytes\n", req->f_info.f_size);

		write(sfd, buf, req->f_info.f_size);
		printf("sent -- %s\n", buf);

		if (req->sendback) {
			readn(sfd, &st, sizeof(status));
			if (st == error) {
				read(sfd, err, sizeof(int));
				printf("error writing file -- %d\n", *err);
				return st;
			}
		}
	}

	return st;
}

size_t send_file1(int out_fd, int in_fd, request_t *req, md5_t *md5) {
	req->sendback = false;
	writen(out_fd, req, sizeof(request_t));
	writen(out_fd, &md5->hash, sizeof(md5->hash));
	size_t sent = sendfile(out_fd, in_fd, &req->f_info.offset, req->f_info.f_size);
	printf("in send_file1, sent -- %zu\n", sent);
	return sent;
}

size_t sendfilen(int out_fd, int in_fd, off_t *offset, size_t count) {
	ssize_t numWritten = 0;
	size_t totWritten;
	printf("\nIN SENDFILEN !!! \n\n");
	for (totWritten = 0; totWritten < count; ) {
		numWritten = sendfile(out_fd, in_fd, offset, count - totWritten);
		printf("offset -- %lu\n", *offset);
		printf("size -- %zu\n", count);
		if (numWritten <= 0) {
		if (numWritten == -1 && errno == EINTR)
			continue;
		else
			return -1;
		}
		totWritten += numWritten;
	}
	printf("totWritten -- %zu\n", totWritten);
	return totWritten;
}


void md5_tostr(unsigned char *digest, md5_t *md5) {
	char tmp[128];
	int i;
	for (i=0; i <MD5_DIGEST_LENGTH; i++) {
		sprintf(tmp+i*2, "%02x",digest[i]);
	}
	memcpy(md5->hash, tmp, 2*MD5_DIGEST_LENGTH);
	md5->hash[2*MD5_DIGEST_LENGTH] = '\0';
}


void get_hash(void *buff, size_t size, md5_t *md5) {
	MD5((unsigned char*) buff, size, md5->hash);
	char tmp[128];
	int i;
	for (i=0; i <MD5_DIGEST_LENGTH; i++) {
		sprintf(tmp+i*2, "%02x", md5->hash[i]);
	}

	memcpy(md5->hash, tmp, 2*MD5_DIGEST_LENGTH);
	md5->hash[2*MD5_DIGEST_LENGTH] = '\0';
}


int init_server(int *fd, remote *server) {
	int sfd;
	struct sockaddr_in addr;
	int ip;

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	inet_pton(AF_INET, server->ip_address, &ip);
	addr.sin_family = AF_INET;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(server->port));
	addr.sin_addr.s_addr = ip;

	int res = connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if (res == 0) {
		*fd = sfd;
	} else {
		fprintf(stderr, "%s\n", "FAILED TO CONNECT");
	}
	return res;
}

request_t *build_req(int raid, command cmd, const char *path,
							struct fuse_file_info *fi, size_t file_size, off_t offset, size_t padding_size) {
	request_t *req = malloc(sizeof(request_t));
	req->raid = raid;
	req->fn = cmd;

	strcpy(req->f_info.path, path);
	req->f_info.padding_size = padding_size;
	req->f_info.f_size = file_size;
	req->f_info.offset = offset;
	if (fi != NULL) {
		req->f_info.flags = fi->flags;
	}
	return req;
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