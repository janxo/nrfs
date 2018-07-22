#include <unistd.h>
#include <errno.h>
#include "rdwrn.h"
#include <stdio.h>


ssize_t readn(int fd, void *buffer, size_t n) {
	printf("!!! IN READN !!!\n");
	ssize_t numRead;
	size_t totRead;
	char *buf;

	buf = buffer;
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


ssize_t writen(int fd, void *buffer, size_t n) {
	printf("!!! IN WRITEN !!!\n");
	ssize_t numWritten;
	size_t totWritten;
	const char *buf;

	buf = buffer;
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