#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include "rdwrn.h"
#include "info.h"
#define BACKLOG 10

request_t req;

void readdir_handler(int cfd, char *buff) {

}

void write1_handler(int cfd, char *buff) {

}

void client_handler(int cfd) {
    printf("IN handler\n");
    // int buf[1024];
    request_t req;
    int data_size;
    printf("Before loop\n");
    while (1) {
        printf("IN the loop\n");
        data_size = read (cfd, &req, sizeof(request_t));
        printf("data_size ---- %d\n", data_size);
        if (data_size <= 0) {
            printf("data size -- %d\n", data_size);
            break;
        }
        printf("raid is -- %d\n", req.raid);
        printf("fn is -- %d\n", req.fn);
        printf("path is -- %s\n", req.path);
        printf("data is -- %s\n", req.buff);
        // write (cfd, &buf, data_size);
    }
    close(cfd);
}



int main(int argc, char* argv[])
{    
    printf("In server main\n");
    int sfd, cfd;
    struct sockaddr_in addr;
    struct sockaddr_in peer_addr;
    int port = atoi(argv[2]); 
    int ip;
    inet_pton(AF_INET, argv[1], &ip);

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip;
    bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
    listen(sfd, BACKLOG);
    
    while (1) 
    {
        socklen_t peer_addr_size = sizeof(struct sockaddr_in);
        cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_size);

        switch(fork()) {
            case -1:
                exit(100);
            case 0:
                close(sfd);
                client_handler(cfd);
                exit(0);
            default:
                continue;
                // close(cfd);
        }
    }
    close(sfd);
}