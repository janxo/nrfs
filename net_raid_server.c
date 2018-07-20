#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include "rdwrn.h"
#include "info.h"
#define BACKLOG 10


char *storage_path;


request_t req;

static void readdir1_handler(int cfd, void *buff) {
    // response_t resp;
    
    status st;
    request_t *req = (request_t *) buff;
    DIR *dp;
    struct dirent *de;
    printf("path is -- %s\n", req->f_info.path);
    int storage_path_len = strlen(storage_path);
    int f_info_len = strlen(req->f_info.path);
    char *path = malloc(storage_path_len + f_info_len + 1);
    strcpy(path, storage_path);
    strcpy(path+storage_path_len, req->f_info.path);
    printf("new paths is -- %s\n", path);
    dp = opendir(path);
    free(path);
    char space = ' ';
    if (dp == NULL) {
        st = error;
    } else {
        st = success;
    }
    write(cfd, &st, sizeof(status));
    int write_len = 0;
    while ((de = readdir(dp)) != NULL) {
        printf("dir entry -- %s\n", de->d_name);
        write_len = writen(cfd, de->d_name, strlen(de->d_name));
        printf("wrote -- %d bytes\n", write_len);
        write_len = writen(cfd, &space, sizeof(space));
        printf("wrote -- %d bytes\n", write_len);
    }
    char enf = '\0';
    write(cfd, &enf, sizeof(enf));
    printf("done\n");
    closedir(dp);

}



static void write1_handler(int cfd, void *buff) {

}

void client_handler(int cfd) {
    printf("IN handler\n");
    // int buf[1024];
    request_t req;
    int data_size;
    printf("Before loop\n");
    while (1) {
        printf("IN the loop\n");
        data_size = readn (cfd, &req, sizeof(request_t));
        if (req.raid == RAID1) {
            switch (req.fn) {
                case cmd_readdir:
                    readdir1_handler(cfd, &req);
                    break;
                default:
                    break;
            }
        }
        printf("sizeof request_t -- %d\n", sizeof(request_t));
        printf("data_size ---- %d\n", data_size);
        if (data_size <= 0) {
            printf("data size less than 0 -- %d\n", data_size);
            break;
        }
        printf("raid is -- %d\n", req.raid);
        printf("fn is -- %d\n", req.fn);
        printf("path is -- %s\n", req.f_info.path);
        printf("flags -- %d\n", req.f_info.flags);
        printf("padding -- %d\n", req.f_info.padding_size);
        // printf("data is -- %s\n", req.buff);
        // write (cfd, &buf, data_size);
    }
    close(cfd);
}



int main(int argc, char* argv[])
{    
    printf("In server main\n");
    storage_path = argv[3];
    printf("storage_path is -- %s\n", storage_path);
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
        // client_handler(cfd);
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