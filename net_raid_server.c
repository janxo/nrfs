#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
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

char *build_path(char *p1, char *p2) {
    int p1_len = strlen(p1);
    int p2_len = strlen(p2);
    char *path = malloc(p1_len+p2_len+1);
    strcpy(path, p1);
    strcpy(path+p1_len, p2);
    return path;
}

static void readdir1_handler(int cfd, void *buff) {
    // response_t resp;
    printf("!!! IN READDIR1 HANDLER !!! \n");
    status st;
    request_t *req = (request_t *) buff;
    DIR *dp;
    struct dirent *de;
    printf("path is -- %s\n", req->f_info.path);
    char *path = build_path(storage_path, req->f_info.path);
    printf("new paths is -- %s\n", path);
    dp = opendir(path);
    free(path);
    char delimiter = ' ';
    if (dp == NULL) {
        st = error;
    } else {
        st = success;
    }
    response_t resp;
    
    memcpy(&resp.st, &st, sizeof(status));
    // write(cfd, &st, sizeof(status));
    int write_len = 0;
    int index = 0;
    while ((de = readdir(dp)) != NULL) {
        printf("dir entry -- %s\n", de->d_name);
        int dir_entry_len = strlen(de->d_name);
        memcpy(resp.buff+index, de->d_name, dir_entry_len);
        index += dir_entry_len;
        resp.buff[index++] = delimiter;
        // write_len = writen(cfd, de->d_name, strlen(de->d_name));
        // printf("wrote -- %d bytes\n", write_len);
        // write_len = writen(cfd, &delimiter, sizeof(delimiter));
        // printf("wrote -- %d bytes\n", write_len);
    }
    int resp_base_size = ((char*) &resp.buff - (char*) &resp);
    resp.packet_size = index + resp_base_size;
    
    // printf("indxex -- %d\n", index);
    printf("about to send -- %d\n", resp.packet_size);
    write_len = writen(cfd, &resp, resp.packet_size);
    printf("sent -- %d\n", write_len);
    printf("sending directories -- %s\n", resp.buff);
    // printf("len -- %zu\n", strlen(resp.buff));
    // char enf = '\0';
    // write(cfd, &enf, sizeof(enf));
    
    printf("!!! READDIR1 DONE !!!\n");
    closedir(dp);

}



static void write1_handler(int cfd, void *buff) {
    printf("!!! IN WRITE HANDLER !!!\n");
    request_t *req = (request_t *) buff;

    struct stat stbuf;
    char *path = build_path(storage_path, req->f_info.path);
    printf("file -- %s\n", path);

    int fd = open(path, req->f_info.flags | O_CREAT, 0644);
    printf("err -- %d\n", errno);
    printf("fd -- %d\n", fd);
    fstat(fd, &stbuf);
    printf("file mode -- %d\n", stbuf.st_mode);
    printf("file flags --%d\n", req->f_info.flags);
    response_t resp;
    printf("status received -- %d\n", req->st);
    int read_n = read(cfd, resp.buff, req->f_info.f_size);
    printf("read -- %d\n", read_n);
    printf("received -- %s\n", resp.buff);

    int res = pwrite(fd, resp.buff, read_n, req->f_info.offset);
    printf("res is -- %d\n", res);
    close(fd);
    
    // last packet of file
    
    if (req->st == done) {
       status write_success = done;
        printf("status sent -- %d\n", write_success);
        
        // notify client whether file write is done or still going
        writen(cfd, &write_success, sizeof(status));
    }
 
    
    printf("!!! END WRITE HANDLER !!! \n");
    
}

static void getattr1_handler(int cfd, void *buff) {
    printf("IN GETATTR HANDLER\n");

    request_t *req = (request_t *) buff;
    struct stat stbuf;
    status st;
    // root dir 
    if (strcmp(req->f_info.path, "/") == 0) {
        // somewhy fstat didn't work on current directory
        st = lstat(storage_path, &stbuf);
        printf("res -- %d\n", st);

    } else {
        char *path = build_path(storage_path, req->f_info.path);
        printf("path -- %s\n", path);
        int fd = open(path, O_CREAT, 0644);
    // printf("fd -- %d\n", fd);
    // status st = lstat(path, &stbuf);
        st = fstat(fd, &stbuf);
        free(path);
        close(fd);
    }
    // file doesn't exist so signal client that it needs to be created

    writen(cfd, &st, sizeof(st));
    writen(cfd, &stbuf, sizeof(stbuf));
    printf("st_mode -- %d\n", stbuf.st_mode);
    printf("sizeof stbuf -- %zu\n", sizeof(stbuf));
    printf("getattr DONE\n");
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
        printf("sizeof request_t -- %lu\n", sizeof(request_t));
        printf("data_size ---- %d\n", data_size);
        if (req.raid == RAID1) {
            switch (req.fn) {
                case cmd_getattr:
                    getattr1_handler(cfd, &req);
                    break;
                case cmd_readdir:
                    readdir1_handler(cfd, &req);
                    break;
                case cmd_write:
                    write1_handler(cfd, &req);
                default:
                    break;
            }
        }
        printf("sizeof request_t -- %lu\n", sizeof(request_t));
        printf("data_size ---- %d\n", data_size);
        if (data_size <= 0) {
            printf("data size less than 0 -- %d\n", data_size);
            break;
        }
        // printf("raid is -- %d\n", req.raid);
        // printf("fn is -- %d\n", req.fn);
        // printf("path is -- %s\n", req.f_info.path);
        // printf("flags -- %d\n", req.f_info.flags);
        // printf("padding -- %d\n", req.f_info.padding_size);
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