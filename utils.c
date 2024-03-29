#include <unistd.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"


ssize_t readn(int fd, const void *buffer, size_t n) {
	ssize_t numRead;
	size_t totRead;
	char *buf;

	buf = (char *) buffer;
	for (totRead = 0; totRead < n; ) {
		numRead = read(fd, buf, n - totRead);
		if (numRead == 0) {
			if (totRead != n) return -1;
			return totRead;
		}
		if (numRead == -1) {
		if (errno == EINTR)
			continue;
		else
			return -1;
		}
		totRead += numRead;
		buf += numRead;
	}
	return totRead;

}



ssize_t writen(int fd, const void *buffer, size_t n) {
	ssize_t numWritten;
	size_t totWritten;
	char *buf;

	buf = (char *) buffer;
	for (totWritten = 0; totWritten < n; ) {
		numWritten = write(fd, buf, n - totWritten);
		
		if (numWritten <= 0) {
			if (totWritten != n) return -1;
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
		close(sfd);
	}
	return res;
}

void build_req(request_t *req, int raid, command cmd, const char *path,
							struct fuse_file_info *fi, size_t file_size, off_t offset, size_t padding_size) {
	req->raid = raid;
	req->fn = cmd;

	
	req->f_info.padding_size = padding_size;
	req->f_info.f_size = file_size;
	req->f_info.offset = offset;
	if (path != NULL)
		strcpy(req->f_info.path, path);
	if (fi != NULL) {
		req->f_info.flags = fi->flags;
	}
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