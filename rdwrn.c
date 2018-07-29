#include <unistd.h>
#include <errno.h>
#include "rdwrn.h"
#include <sys/sendfile.h>
#include <stdio.h>
#include <string.h>


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


size_t sendfilen(int out_fd, int in_fd, off_t offset, size_t count) {
	ssize_t numWritten = 0;
	size_t totWritten;
	printf("\nIN SENDFILEN !!! \n\n");
	for (totWritten = 0; totWritten < count; ) {
		numWritten = sendfile(out_fd, in_fd, &offset, count - totWritten);
		printf("offset -- %lu\n", offset);
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


// void get_hash(void *buff, size_t size, md5_t *md5) {
// 	// printf("\nABOUT TO CALCULATE HASH\n\n");
// 	MD5((unsigned char*) buff, size, md5->hash);
// 	print_md5_sum(md5);
// 	char tmp[128];
// 	int i;
// 	for (i=0; i <MD5_DIGEST_LENGTH; i++) {
// 		sprintf(tmp+i*2, "%02x",md5->hash[i]);
// 	}
// 	printf("\n\n");
// 	// printf("\nmd5 is -- %s\n", tmp);
// 	// printf("len is -- %zu\n", strlen(tmp));
// 	// printf("digest len -- %d\n", strlen());
// 	memcpy(md5->hash, tmp, 2*MD5_DIGEST_LENGTH);
// 	md5->hash[2*MD5_DIGEST_LENGTH] = '\0';
// 	// printf("\nmd5 is -- %s\n", md5->hash);
// }