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
#include <pthread.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include "zlib.h"
#include "utils.h"
#include "info.h"


#define BACKLOG 10
#define MAX_EVENTS 10

struct epoll_event ev, events[MAX_EVENTS];
int epoll_fd, nfds, nclients;
pthread_t thread_pool[MAX_EVENTS];

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
    printf("path -- %s\n", path);
    status fd = open(path, req->f_info.flags, req->f_info.mode);
    printf("fd -- %d\n", fd);
    printf("fsize -- %zu\n", req->f_info.f_size);
    if (req->sendback)
        writen(cfd, &fd, sizeof(status));
    if (fd == error && req->sendback) {
        fd = errno;
        printf("err -- %d\n", errno);
        printf("fd -- %d\n", fd);
        writen(cfd, &fd, sizeof(status));
    } else {

        // md5_t md5;
        char *file_chunk = malloc(req->f_info.f_size);
        int read_n;
        // printf("status received -- %d\n", req->st);
        // int read_n = readn(cfd, &md5.hash, sizeof(md5.hash));
        // printf("read -- %d\n", read_n);
        // printf("received hash-- %s\n", md5.hash);
        read_n = readn(cfd, file_chunk, req->f_info.f_size);
        printf("read -- %d\n", read_n);
        // printf("received file-- %s\n", file_chunk);
    
        status res = pwrite(fd, file_chunk, read_n, req->f_info.offset);
        printf("res is -- %d\n", res);
        if (req->sendback) {
            writen(cfd, &res, sizeof(status));
            if (res == error) {
                printf("error writing file\n");
                int err = errno;
                writen(cfd, &err, sizeof(err));
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
    int fd = open(path, O_RDONLY);
    printf("path -- %s\n", path);
    st = stat(path, &stbuf);
    printf("st -- %d\n", st);
    writen(cfd, &st, sizeof(st));
    
    if (st == error) {
        printf("sizeof errno is -- %lu\n", sizeof(errno));
        printf("error -- %d\n", errno);
        int res = errno;
        printf("res is %d\n", res);
        writen(cfd, &res, sizeof(res));
    } else {
        size_t sent = writen(cfd, &stbuf, sizeof(struct stat));
        printf("struct stat size -- %zu\n", sizeof(struct stat));
        printf("sent -- %zu\n", sent);
    }
    printf("st size -- %zu\n", stbuf.st_size);

    close(fd);
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
            // close(st);
        }
    }
    close(st);
    free(path);

    printf("!!! CREATE1 DONE !!! \n");
}


static void open1_handler(int cfd, void *buff) {
    printf("!!! OPEN1 HANDLER !!!\n");
    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    status st = open(path, req->f_info.flags);
    printf("path -- %s\n", path);
    printf("open status -- %d\n", st);

    md5_t md5_attr;
    status match;

    int attr_present = getxattr(path, ATTR_HASH, &md5_attr.hash, sizeof(md5_attr.hash));
    struct stat stbuf;
    fstat(st, &stbuf);

    if (attr_present == -1 || stbuf.st_size == 0) {
        printf("no attr or size is 0\n");
        match = hash_mismatch;
        memset(&md5_attr, 0, sizeof(md5_attr));
    } else {
        
        int fd = open(path, O_RDONLY);
        void *buff = mmap(NULL, stbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
        printf("errno -- %d\n", errno);
        assert(buff != MAP_FAILED);
        md5_t md5_curr;
        get_hash(buff, stbuf.st_size, &md5_curr);

        int cmp = strcmp((const char*)md5_attr.hash, (const char*)md5_curr.hash);

        if (cmp == 0) {
            printf("hash match\n");
            match = hash_match;
           
        } else {
            printf("hash mismatch\n");
            match = hash_mismatch;
        }
        close(fd);
    }

    writen(cfd, &match, sizeof(status));
    writen(cfd, &md5_attr, sizeof(md5_t));
    writen(cfd, &stbuf.st_size, sizeof(stbuf.st_size));

    close(st);
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

    struct timespec ts[2];

    readn(cfd, ts, 2*sizeof(struct timespec));

    status st = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
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
    printf("status -- %d\n", st);
    printf("offset -- %lu\n", req->f_info.offset);
    printf("should send -- %zu\n", req->f_info.f_size);
    if (st == error) {
        int res = errno;
        writen(cfd, &res, sizeof(res));
    } else {
        // send dummy for edge case
        // when file size is 0
        // client will block on read if we don't send anyhting
        // so we send dummy bytes
        // status dum = dummy;
        // writen(cfd, &dum, sizeof(status));
        size_t toSend = 0;
        struct stat stbuf;
        fstat(st, &stbuf);
        toSend = stbuf.st_size - req->f_info.offset;
        if (toSend > req->f_info.f_size) {
            toSend = req->f_info.f_size;
        }
        printf("toSend -- %zu\n", toSend);
        writen(cfd, &toSend, sizeof(size_t));
        size_t sent = sendfile(cfd, st, &req->f_info.offset, toSend);
        printf("sent -- %zu\n", sent);
    }
    close(st);
    printf("!!! READ1 DONE !!!\n");
}

static void rmdir1_handler(int cfd, void *buff) {
    printf("!!! RMDIR1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);

    status st = rmdir(path);
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

    status st = rename(path, new_name);
    if (req->sendback) {
    writen(cfd, &st, sizeof(status));
        if (st == error) {
            int res = errno;
            writen(cfd, &res, sizeof(res));
        }
    }
    free(path);
    free(new_name);
    printf("!!! RENAME1 DONE !!!\n");
}

static void release1_handler(int cfd, void *buff) {
    printf("!!! RELEASE1 HANDLER !!!\n");

    request_t *req = (request_t *) buff;
 
    md5_t md5;
    printf("received path -- %s\n", req->f_info.path);
    char *path = build_path(storage_path, req->f_info.path);
    int fd = open(path, O_RDONLY);
    struct stat stbuf;
    fstat(fd, &stbuf);
   
    void *file = mmap(NULL, stbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(buff != MAP_FAILED);
    get_hash(file, stbuf.st_size, &md5);
    printf("hash --- %s\n", md5.hash);
    status res = setxattr(path, ATTR_HASH, md5.hash, sizeof(md5.hash), XATTR_REPLACE);
    if (res == error) {
        setxattr(path, ATTR_HASH, md5.hash, sizeof(md5.hash), XATTR_CREATE);
    }
    munmap(file, stbuf.st_size);

    close(fd);
    free(path);

    printf("!!! RELEASE1 DONE !!!\n");
}

static void truncate1_handler(int cfd, void *buff) {
    printf("!!! TRUNCATE1 HANDLER !!!\n");
    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, req->f_info.path);
    status st = truncate(path, req->f_info.f_size);

    if (req->sendback) {
        writen(cfd, &st, sizeof(status));
        if (st == error) {
            writen(cfd, &errno, sizeof(errno));
        }
    }

    free(path);

    printf("!!! TRUNCATE1 DONE !!!\n");
}



static void restore1_file_handler(int cfd, void *buff) {
    printf("!!! RESTORE1_FILE HANDLER !!!\n");

    request_t *req = (request_t *) buff;
    remote send_to_server;
    readn(cfd, &send_to_server, sizeof(remote));
    int sendfd;
    printf("addr -- %s\n", send_to_server.ip_address);
    printf("port -- %s\n", send_to_server.port);
    init_server(&sendfd, &send_to_server);
    struct stat stbuf;
    char *path = build_path(storage_path, req->f_info.path);
    int fd = open(path, O_RDONLY);
    fstat(fd, &stbuf);
    req->fn = cmd_unlink;
    req->sendback = false;
    writen(sendfd, req, sizeof(request_t));
    req->fn = cmd_write;
    req->f_info.flags = O_CREAT | O_WRONLY;
    req->f_info.mode = stbuf.st_mode;
    req->f_info.f_size = stbuf.st_size;
    req->f_info.offset = 0;
    
    // md5_t md5;
    // getxattr(path, ATTR_HASH, &md5.hash, sizeof(md5.hash));
    writen(sendfd, req, sizeof(request_t));
    
    sendfile(sendfd, fd, &req->f_info.offset, req->f_info.f_size);
    // write hashes
    req->fn = cmd_release;
    printf("path -- %s\n", req->f_info.path);
    writen(sendfd, req, sizeof(request_t));
    // writen(sendfd, &md5, sizeof(md5_t));
    close(fd);
    close(sendfd);
    free(path);

    printf("!!! RESTORE1_FILE DONE !!!\n");
}


static void restore1_dir_handler(int cfd, void *buff) {
    printf("!!! RESTORE1_DIR HANDLER !!!\n");
    request_t *req = (request_t *) buff;
    char *path = build_path(storage_path, ZIPFILE);
    // compress folder
    if (req->f_info.mode == send_to_server) {
        printf("should send to server\n");
        int pid = fork();
        if (pid == 0) {
            execl("/bin/tar", "tar", "-czf", path, storage_path, NULL);
        }
        int status;
        wait(&status);
        // connect to server and send compressed data to it
        remote send_to_server;
        readn(cfd, &send_to_server, sizeof(remote));
    
        int sendfd;
        init_server(&sendfd, &send_to_server);
        struct stat stbuf;
        int fd = open(path, O_RDONLY);
        fstat(fd, &stbuf);
        request_t send_req;
        build_req(&send_req, RAID1, cmd_write, ZIPFILE, NULL, stbuf.st_size, 0, 0);
        send_req.sendback = false;
        send_req.f_info.flags = O_CREAT | O_WRONLY;
        send_req.f_info.mode = stbuf.st_mode;
    

        writen(sendfd, &send_req, sizeof(request_t));
        sendfile(sendfd, fd, &send_req.f_info.offset, send_req.f_info.f_size);
        
        // notify server to decompress received data
        send_req.fn = cmd_restore_dir;
        send_req.f_info.mode = receive_from_server;
        writen(sendfd, &send_req, sizeof(request_t));

        close(fd);
        unlink(path);   // delete compressed data
        free(path);

    } else if (req->f_info.mode == receive_from_server) {
        // decompress data and delete compressed data
        printf("should receive from server\n");
        int pid;
        pid = fork();
        if (pid == 0) {
            execl("/bin/tar", "tar", "--strip-components", "1", "-xzf", path, "-C", storage_path, NULL);
        }
        int status;
        wait(&status);
        unlink(path);
    }
    printf("!!! RESTORE1_DIR DONE !!!\n");
}

void *client_handler(void *data) {
    printf("In handler\n");
    int cfd = *(int*)data;
    request_t req;
    int data_size;
    printf("Before loop\n");
    while (1) {
        printf("IN the loop\n");
        printf("cfd -- %d\n", cfd);
        data_size = readn (cfd, &req, sizeof(request_t));

        if (req.raid == RAID1) {
            switch (req.fn) {
                case cmd_getattr:           getattr1_handler(cfd, &req);        break;
                case cmd_utimens:           utimens1_handler(cfd, &req);        break;
                case cmd_access:            access1_handler(cfd, &req);         break;
                case cmd_open:              open1_handler(cfd, &req);           break;
                case cmd_create:            create1_handler(cfd, &req);         break;
                case cmd_readdir:           readdir1_handler(cfd, &req);        break;
                case cmd_read:              read1_handler(cfd, &req);           break;
                case cmd_write:             write1_handler(cfd, &req);          break;
                case cmd_unlink:            unlink1_handler(cfd, &req);         break;
                case cmd_mkdir:             mkdir1_handler(cfd, &req);          break;
                case cmd_rmdir:             rmdir1_handler(cfd, &req);          break;
                case cmd_rename:            rename1_handler(cfd, &req);         break;
                case cmd_truncate:          truncate1_handler(cfd, &req);       break;
                case cmd_release:           release1_handler(cfd, &req);        break;
                case cmd_restore_file:      restore1_file_handler(cfd, &req);   break;
                case cmd_restore_dir:       restore1_dir_handler(cfd, &req);    break;
                default: break;
            }
        }
     
        if (data_size <= 0) {
            printf("data size less than 0 -- %d\n", data_size);
            break;
        }
    }
    close(cfd);

    pthread_exit(NULL);
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
    

    epoll_fd = epoll_create1(0);
    ev.data.fd = sfd;
    ev.events = EPOLLIN;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev);

    while (1) 
    {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        int n;
        for (n = 0; n < nfds; ++n) {
            // printf("n -- %d\n", n);
            if (events[n].data.fd == sfd) {
                socklen_t peer_addr_size = sizeof(struct sockaddr_in);
                cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_size);

                // ev.events = EPOLLIN | EPOLLET;
                // ev.data.fd = cfd;

                // epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &ev);
                pthread_create(&thread_pool[nclients++], NULL, client_handler, &cfd);
            }
        }

    }
    close(sfd);
}