#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/xattr.h>
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
    char *path = build_path(storage_path, req->f_info.path);
    dp = opendir(path);
    free(path);
    
    if (dp == NULL) {
        st = error;
        writen(cfd, &st, sizeof(status));
        int res = errno;
        writen(cfd, &res, sizeof(res));
    } else {
        st = success;
        writen(cfd, &st, sizeof(status));

        char delimiter = ',';
        response_t resp;
        memset(resp.buff, 0, sizeof(resp.buff));

        int index = 0;
        while ((de = readdir(dp)) != NULL) {
            printf("dir entry -- %s\n", de->d_name);
            int dir_entry_len = strlen(de->d_name);
            memcpy(resp.buff+index, de->d_name, dir_entry_len);
            index += dir_entry_len;
            resp.buff[index++] = delimiter;
        }

        resp.packet_size = index;
        
        writen(cfd, &resp.packet_size, sizeof(resp.packet_size));
        writen(cfd, resp.buff, resp.packet_size);
        printf("sending directories -- %s\n", resp.buff);
    }


    printf("!!! READDIR1 DONE !!!\n");
    closedir(dp);

}



static void write1_handler(int cfd, void *buff) {
    printf("!!! IN WRITE HANDLER !!!\n");
    request_t *req = (request_t *) buff;

    char *path = build_path(storage_path, req->f_info.path);

    status fd = open(path, req->f_info.flags, req->f_info.mode);
   
    writen(cfd, &fd, sizeof(status));
    if (fd == error) {
        fd = errno;
        printf("err -- %d\n", errno);
        printf("fd -- %d\n", fd);
        writen(cfd, &fd, sizeof(status));
    } else {

        md5_t md5;
        char *file_chunk = malloc(req->f_info.f_size);
        // printf("status received -- %d\n", req->st);
        int read_n = readn(cfd, &md5.hash, sizeof(md5.hash));
        printf("read -- %d\n", read_n);
        printf("received -- %s\n", md5.hash);
        read_n = readn(cfd, file_chunk, req->f_info.f_size);
        printf("read -- %d\n", read_n);
        printf("received -- %s\n", file_chunk);
    
        status res = pwrite(fd, file_chunk, read_n, req->f_info.offset);
        printf("res is -- %d\n", res);
        writen(cfd, &res, sizeof(status));
        if (res == error) {
            printf("error writing file\n");
            int err = errno;
            writen(cfd, &err, sizeof(err));
        } else {
            res = setxattr(path, ATTR_HASH, md5.hash, sizeof(md5.hash), XATTR_CREATE);
            char chunk_size[32];
            char chunk_offset[32];
            sprintf(chunk_size, "%zu", req->f_info.f_size);
            sprintf(chunk_offset, "%lu", req->f_info.offset);
            setxattr(path, ATTR_SIZE, chunk_size, strlen(chunk_size), XATTR_CREATE);
            setxattr(path, ATTR_OFFSET, chunk_offset, strlen(chunk_offset), XATTR_CREATE);
            printf("xattr res -- %d -- %d\n", res, -errno);
            if (res == error) {
                res = setxattr(path, ATTR_HASH, md5.hash, sizeof(md5.hash), XATTR_REPLACE);
                setxattr(path, ATTR_SIZE, chunk_size, strlen(chunk_size), XATTR_REPLACE);
                setxattr(path, ATTR_OFFSET, chunk_offset, strlen(chunk_offset), XATTR_REPLACE);
                printf("xattr res1 -- %d -- %d\n", res, -errno);


            }
        }
        free(file_chunk);
    }
     
    
    close(fd);
    free(path);
    printf("!!! END WRITE HANDLER !!! \n");
    
}

static void getattr1_handler(int cfd, void *buff) {
    printf("!!! IN GETATTR HANDLER !!! \n");

    request_t *req = (request_t *) buff;
    struct stat stbuf;
    status st;
    char *path = build_path(storage_path, req->f_info.path);
    st = lstat(path, &stbuf);

    writen(cfd, &st, sizeof(st));
    
    if (st == error) {
        printf("sizeof errno is -- %lu\n", sizeof(errno));
        printf("error -- %d\n", errno);
        int res = errno;
        printf("res is %d\n", res);
        writen(cfd, &res, sizeof(res));
    } else {
        writen(cfd, &stbuf, sizeof(stbuf));
    }
    printf("st size -- %zu\n", stbuf.st_size);
    free(path);
    printf("!!! GETATTR DONE !!! \n");
}


static void create1_handler(int cfd, void *buff) {
    printf("!!! IN CREATE1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    // printf("mode -- %d\n", req->f_info.mode);
    status st = open(path, req->f_info.flags, req->f_info.mode);

    if (req->sendback) {
        writen(cfd, &st, sizeof(status));
        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        } else {
            close(st);
        }
    }

    free(path);

    printf("!!! CREATE1 DONE !!! \n");
}


static void open1_handler(int cfd, void *buff) {
    printf("!!! OPEN1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    status st = open(path, req->f_info.flags);

    status res;

    md5_t md5_attr;
    int attr_present = getxattr(path, ATTR_HASH, &md5_attr.hash, sizeof(md5_attr.hash));

    if (attr_present == -1) {
        printf("No attributes yet\n");
        res = no_attr;
        writen(cfd, &res, sizeof(status));
    } else {
        res = sending_attr;
        writen(cfd, &res, sizeof(status));

        char chunk_size_str[32];
        char chunk_offset_str[32];
        getxattr(path, ATTR_SIZE, chunk_size_str, sizeof(chunk_size_str));
        getxattr(path, ATTR_OFFSET, chunk_offset_str, sizeof(chunk_offset_str));

        size_t chunk_size = atoi(chunk_size_str);
        off_t chunk_offset = atoi(chunk_offset_str);

        printf("attr size -- %zu\n", chunk_size);
        printf("attr ofset -- %lu\n", chunk_offset);

        void *buff = mmap(0, chunk_size, PROT_READ, MAP_SHARED, st, chunk_offset);

        md5_t md5_curr;
        get_hash(buff, chunk_size, &md5_curr);

        printf("hash_attr -- %s\n", md5_attr.hash);
        printf("hash_curr -- %s\n", md5_curr.hash);

        int cmp = strcmp((const char*)md5_attr.hash, (const char*)md5_curr.hash);
        status match;
        if (cmp == 0) {
            printf("hash match\n");
            match = hash_match;
           
        } else {
            printf("hash mismatch\n");
            match = hash_mismatch;
        }

        printf("sending status %d\n", match);
        writen(cfd, &match, sizeof(status));
        writen(cfd, &md5_curr.hash, sizeof(md5_curr.hash));
        

    }

    // writen(cfd, &st, sizeof(status));
    // if (st == error) {
    //     int res = errno;
    //     writen(cfd, &res, sizeof(res));
    // } else {
    //     close(st);
    // }


    free(path);

    printf("!!! OPEN1 DONE !!! \n");
}

static void access1_handler(int cfd, void *buff) {
    printf("!!! ACCESS1 HANDLER !!!\n");
    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    status st = access(path, req->f_info.mask);

    if (req->sendback) {
        writen(cfd, &st, sizeof(status));

        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        }
    }

    free(path);
    printf("!!! ACCESS1 DONE !!! \n");
}


static void utimens1_handler(int cfd, void *buff) {
    printf("!!! UTIMENS1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    // printf("path -- %s\n", path);

    struct timespec ts[2];
    // printf("add0 -- %d\n", ts);
    // printf("add1 -- %d\n", &ts);
    readn(cfd, ts, 2*sizeof(struct timespec));
    // printf("time0 --- %s\n", ctime(&(ts[0].tv_sec)));
    // printf("time1 --- %s\n", ctime(&(ts[1].tv_sec)));
    // printf("shouldve read -- %zu\n", 2*sizeof(struct timespec));
    // printf("actually read -- %d\n", read_n);
    // printf("no follow -- %d\n", req->f_info.mask);

    status st = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
    // printf("stus -- %d\n", st);
    if (req->sendback) {
        writen(cfd, &st, sizeof(status));


        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        }
    }

    free(path);
    printf("!!! UTIMENS1 DONE !!! \n");
}

static void unlink1_handler(int cfd, void *buff) {
    printf("!!! UNLINK1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);

    status st = unlink(path);
    if (req->sendback) {
        writen(cfd, &st, sizeof(status));

        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        }
    }

    free(path);
    printf("!!! UNLINK1 DONE !!!\n");
}


static void mkdir1_handler(int cfd, void *buff) {
    printf("!!! MKDIR1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    // printf("path0 -- %s\n", req->f_info.path);
    // printf("path1 -- %s\n", path);
    status st = mkdir(path, req->f_info.mode);

    if (req->sendback) {
        writen(cfd, &st, sizeof(status));
        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        }
    }

    free(path);
    printf("!!! MKDIR1 DONE !!!\n");
}

static void read1_handler(int cfd, void *buff) {
    printf("!!! READ1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);

    status st = open(path, req->f_info.flags);
    writen(cfd, &st, sizeof(status));
    // printf("status -- %d\n", st);
    // printf("offset -- %lu\n", req->f_info.offset);
    // printf("should send -- %zu\n", req->f_info.f_size);
    if (st == error) {
        int res = errno;
        writen(cfd, &res, sizeof(res));
    } else {
        // send dummy for edge case
        // when file size is 0
        // client will block on read if we don't send anyhting
        // so we send dummy bytes
        status dum = dummy;
        writen(cfd, &dum, sizeof(status));
        size_t sent = sendfile(cfd, st, &req->f_info.offset, READ_CHUNK_LEN);
        printf("sent -- %zu\n", sent);
        close(st);
    }



    printf("!!! READ1 DONE !!!\n");
}

static void rmdir1_handler(int cfd, void *buff) {
    printf("!!! RMDIR1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    // printf("path0 -- %s\n", req->f_info.path);
    // printf("path1 -- %s\n", path);
    status st = rmdir(path);
    // printf("status -- %d\n", st);
    if (req->sendback) {
        writen(cfd, &st, sizeof(status));
        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        }
    }

    free(path);

    printf("!!! RMDIR1 DONE !!!\n");
}

static void rename1_handler(int cfd, void *buff) {
    printf("!!! RENAME1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    char to[64];

    size_t len;
    readn(cfd, &len, sizeof(size_t));
    readn(cfd, to, len);
    char *new_name = build_path(storage_path, to);

    // printf("path0 -- %s\n", path);
    // printf("path1 -- %s\n", new_name);
    status st = rename(path, new_name);
    // printf("status -- %d\n", st);
    writen(cfd, &st, sizeof(status));
    if (st == error) {
        int res = errno;
        writen(cfd, &res, sizeof(res));
    }

    free(path);
    free(new_name);
    printf("!!! RENAME1 DONE !!!\n");
}


void restore_handler(int cfd, void *buff) {
    printf("!!! RESTORE HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    printf("path -- %s\n", req->f_info.path);
    if (req->f_info.mode == send_to_server) {
        printf("should send to server\n");
        remote send_to_server;
        readn(cfd, &send_to_server, sizeof(remote));

        printf("addr -- %s\n", send_to_server.ip_address);
        printf("port -- %s\n", send_to_server.port);

        int sendfd;
        int res = init_server(&sendfd, &send_to_server);
        printf("res %d -- fd -- %d\n", res, sendfd);

        req->f_info.mode = receive_from_server;
        writen(sendfd, req, sizeof(request_t));
    } else if (req->f_info.mode == receive_from_server) {
        printf("should receive from server\n");
    }


    printf("!!! RESTORE DONE !!!\n");
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
                case cmd_getattr:
                    getattr1_handler(cfd, &req);
                    break;
                case cmd_utimens:
                    utimens1_handler(cfd, &req);
                    break;
                case cmd_access:
                    access1_handler(cfd, &req);
                    break;
                case cmd_open:
                    open1_handler(cfd, &req);
                    break;
                case cmd_create:
                    create1_handler(cfd, &req);
                    break;
                case cmd_readdir:
                    readdir1_handler(cfd, &req);
                    break;
                case cmd_read:
                    read1_handler(cfd, &req);
                    break;
                case cmd_write:
                    write1_handler(cfd, &req);
                    break;
                case cmd_unlink:
                    unlink1_handler(cfd, &req);
                    break;
                case cmd_mkdir:
                    mkdir1_handler(cfd, &req);
                    break;
                case cmd_rmdir:
                    rmdir1_handler(cfd, &req);
                    break;
                case cmd_rename:
                    rename1_handler(cfd, &req);
                case cmd_restore:
                    restore_handler(cfd, &req);
                default:
                    break;
            }
        }
 
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