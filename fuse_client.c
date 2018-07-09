#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <arpa/inet.h>
#include "info.h"
#include "parse.h"
#include "tst.h"



void init_connection(strg_info_t *strg) {
	printf("IN client main\n");
    int sfd;
    struct sockaddr_in addr;
    int ip;
    char buf[1024];
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    inet_pton(AF_INET, "127.0.0.1", &ip);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = ip;

    connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
    write(sfd, "qwe", 3);
    read(sfd, &buf, 3);
    printf("%s\n", buf);
    //sleep(600);
    close(sfd);
}



static struct fuse_operations nrfs1_oper = {
	// .getattr	= nrfs1_getattr,
	// .readdir	= nrfs1_readdir,
	// .open		= nrfs1_open,
	// .read		= nrfs1_read,
};




int main(int argc, char *argv[]) {

	// printf("FREEE\n");
	// printf("storage %s\n", argv[2]);

	strg_info_t strg;
	
	init_storage(argv[1], argv[2], &strg);

	test_storage(&strg);

	// return fuse_main(argc, argv, &nrfs1_oper, NULL);
	return 0;
}