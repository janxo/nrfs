#include "parse.h"
#include "config.h"
#include <stdbool.h>

#define MAXLEN 80
#define MAXLEN_VAL 1024
#define BUFFLEN 1024

void parse_server(remote *server, char *value);
void parse_servers(storage *storage,  char *servers);
int get_disknames(char *path, char **disknames);


/** counts number of storages and copies storage names
    into passed string array.
    */ 
int get_disknames(char *path, char **disknames) {
  int res = 0;
  char *s, buff[BUFFLEN];
  FILE *fp = fopen (path, "r");
  if (fp == NULL) return -1;
   while ((s = fgets (buff, sizeof(buff), fp)) != NULL) {
    /* Skip blank lines and comments */
    if (buff[0] == '\n' || buff[0] == '#')
      continue;

    char name[MAXLEN], value[MAXLEN_VAL];
    s = strtok (buff, " =");
    if (s==NULL) {
      break;
    } else {
      strcpy(name, s);    }
    s = strtok (NULL, "= \n");
    if (s==NULL){
      break;
    } else {
      strcpy(value, s);
    }

    if (strcmp(name, DISKNAME) == 0) {
      int len = strlen(value);
      disknames[res] = malloc(len+1);
      strcpy(disknames[res++], value);
    }
  }
  fclose(fp);
  return res;
}

void init_storage(char *path, char *diskname, strg_info_t *storage_info) {
  bool storage_match = false;
  char *s, buff[BUFFLEN];
  
  FILE *fp = fopen (path, "r");
  // printf("%s\n", path);
  if (fp == NULL)
  {
    return;
  }
  /* Read next line */
  while ((s = fgets (buff, sizeof buff, fp)) != NULL) {
/* Skip blank lines and comments */
    if (buff[0] == '\n' || buff[0] == '#')
      continue;

    char name[MAXLEN], value[MAXLEN_VAL];
    s = strtok (buff, " =");
    if (s==NULL) {
      break;
    } else {
      strcpy(name, s);
    }
    s = strtok (NULL, "=\n");
    if (s==NULL){
      break;
    } else {
      strcpy(value, s+1);
    }
    
 
    if (strcmp(name, ERRORLOG) == 0) {
      strcpy (storage_info->errorlog, value);

    } else if (strcmp(name, CACHE_SIZE) == 0) {
      strcpy (storage_info->cache_size, value);

    } else if (strcmp(name, CACHE_REPLACEMENT) == 0) {
      strcpy (storage_info->cache_replacement, value);

    } else if (strcmp(name, TIMEOUT) == 0) {
      storage_info->timeout = atoi(value);

    } else if ((strcmp(name, DISKNAME) == 0) && strcmp(diskname, value) == 0) {
      storage_match = true;
      strcpy (storage_info->strg.diskname, value);

    } else if (strcmp(name, MOUNTPOINT) == 0 && storage_match) {
      strcpy (storage_info->strg.mountpoint, value);

    } else if (strcmp(name, RAID) == 0 && storage_match) {
      storage_info->strg.raid = atoi(value);

    } else if (strcmp(name, SERVERS) == 0 && storage_match) {
      storage *cur_storage = &storage_info->strg;
      cur_storage->server_count = 0;
      parse_servers(cur_storage, value);

    } else if (strcmp(name, HOTSWAP) == 0 && storage_match) {
      parse_server(&storage_info->strg.hotswap, value);
      break;
    } else {
      // printf("WARNING: %s/%s: Unknown name/value pair!\n", name, value);
    }
  }
  fclose (fp);
}

/** 
 *  Receives single server address splints it
 *  and initializes it. First part of token is
 *  address, second part is port.
 */
void parse_server(remote *server, char *value) {
  char *tok_s;

  char *tok = strtok_r(value, ": ", &tok_s);

  strcpy(server->ip_address, tok);
  tok = strtok_r(NULL, " ", &tok_s);
  strcpy(server->port, tok);
}

void parse_servers(storage *storage,  char *servers) {
  char *tok_s;
  char *tok = strtok_r(servers, ",", &tok_s);
  
  while (tok != NULL) {
    parse_server(&storage->servers[storage->server_count], tok);
    storage->server_count++;
    tok = strtok_r(NULL, ",", &tok_s);
  }
}
