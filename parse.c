#include "parse.h"
#include "config.h"
#include <stdbool.h>

#define MAXLEN 80
#define MAXLEN_VAL 1024
#define BUFFLEN 1024

void parse_server(remote *server, char *value);
void parse_servers(storage *storage,  char *servers);
int get_disknames(char *path, char **disknames);


/*
 * trim: get rid of trailing and leading whitespace...
 *       ...including the annoying "\n" from fgets()
 */
char *
trim (char * s)
{
  /* Initialize start, end pointers */
  char *s1 = s, *s2 = &s[strlen (s) - 1];

  /* Trim and delimit right side */
  while ( (isspace (*s2)) && (s2 >= s1) )
    s2--;
  *(s2+1) = '\0';

  /* Trim left side */
  while ( (isspace (*s1)) && (s1 < s2) )
    s1++;

  /* Copy finished string */
  strcpy (s, s1);
  return s;
}


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
    s = strtok (buff, "=");
    if (s==NULL) {
      break;
      // continue;
    } else {
      strncpy (name, s, MAXLEN);
      *strchr (name, ' ') = '\0';
    }
    s = strtok (NULL, "=");
    if (s==NULL)
      break;
      // continue;
    else
      strncpy (value, s, MAXLEN_VAL);

    if (strcmp(name, DISKNAME) == 0) {
      // -2 because of space before and '\n' after
      int len = strlen(value) - 2;
      disknames[res] = malloc(len+1);

      value[len+1] = '\0';
      strncpy(disknames[res], value+1, strlen(value));
      res++;
    }
  }
  fclose(fp);
  return res;
}

void init_storage(char *path, char *diskname, strg_info_t *storage_info) {
  bool storage_match = false;
  char *s, buff[BUFFLEN];
  printf("INITIALIZING STORAGE\n");
  printf("STORAGE SIZE -- %d\n", sizeof(strg_info_t));
  FILE *fp = fopen (path, "r");
  // printf("%s\n", path);
  if (fp == NULL)
  {
    return;
  }
  // printf("SUCCES OPEN\n");
  /* Read next line */
  while ((s = fgets (buff, sizeof buff, fp)) != NULL) {
    /* Skip blank lines and comments */
    if (buff[0] == '\n' || buff[0] == '#')
      continue;

    /* Parse name/value pair from line */
    char name[MAXLEN], value[MAXLEN_VAL];
    s = strtok (buff, "=");
    if (s==NULL)
      continue;
    else {
      strncpy (name, s, MAXLEN);
      *strchr (name, ' ') = '\0';
    }
    s = strtok (NULL, "=");
    if (s==NULL)
      continue;
    else
      strncpy (value, s, MAXLEN_VAL);
    trim (value);
    // printf("NAME -- %s\n", name);
    // printf("VALUE -- %s\n", value);
    if (strcmp(name, ERRORLOG) == 0) {
      strncpy (storage_info->errorlog, value, MAXLEN);
      printf ("info errorlog --%s\n", storage_info->errorlog);
    } else if (strcmp(name, CACHE_SIZE) == 0) {
      strncpy (storage_info->cache_size, value, MAXLEN);
      printf ("cache __ %s\n", storage_info->cache_size);
    } else if (strcmp(name, CACHE_REPLACEMENT) == 0) {
      strncpy (storage_info->cache_replacement, value, MAXLEN);
      printf ("cache repl __ %s\n", storage_info->cache_replacement);
    } else if (strcmp(name, TIMEOUT) == 0) {
      storage_info->timeout = atoi(value);
      printf ("timeout is -- %d\n", storage_info->timeout);
    } else if ((strcmp(name, DISKNAME) == 0) && strcmp(diskname, value) == 0) {
      storage_match = true;
      strncpy (storage_info->strg.diskname, value, MAXLEN);
      printf ("diskname -- %s\n", storage_info->strg.diskname);
    } else if (strcmp(name, MOUNTPOINT) == 0 && storage_match) {
      strncpy (storage_info->strg.mountpoint, value, MAXLEN);
      printf ("mount point -- %s\n", storage_info->strg.mountpoint);
    } else if (strcmp(name, RAID) == 0 && storage_match) {
      storage_info->strg.raid = atoi(value);
      printf ("raid -- %d\n", storage_info->strg.raid);
    } else if (strcmp(name, SERVERS) == 0 && storage_match) {
      storage *cur_storage = &storage_info->strg;
      cur_storage->server_count = 0;
      parse_servers(cur_storage, value);
      // break;
    } else if (strcmp(name, HOTSWAP) == 0 && storage_match) {
      printf("hotswap -- %s\n", value);
      printf("%d\n", sizeof(storage_info->strg.hotswap));
      parse_server(&storage_info->strg.hotswap, value);
      break;
    } else {
      // printf("WARNING: %s/%s: Unknown name/value pair!\n", name, value);
    }
  }
  printf("CLOSING FILE\n");
  fclose (fp);
}

/** 
 *  Receives single server address splints it
 *  and initializes it. First part of token is
 *  address, second part is port.
 */
void parse_server(remote *server, char *value) {
  char *tok_s;
  printf("IN PARSE SERVER\n");
  printf("Server is --%s\n", value);
  char *tok = strtok_r(value, ": ", &tok_s);
  printf("value is --%s\n", value);
  printf("tok is --%s\n", tok);
  printf("%d -- %d\n", sizeof(server->ip_address), sizeof(tok));
  // strncpy(server->ip_address, "127.0.0.1", MAXLEN);
  strncpy(server->ip_address, tok, MAXLEN);
  printf("server address --%s\n", server->ip_address);
  tok = strtok_r(NULL, " ", &tok_s);
  printf("tok is --%s\n", tok);
  // strncpy(server->ip_address, "22222", MAXLEN);
  strncpy(server->port, tok, MAXLEN);
  printf("server port is --%s\n", server->port);
}

void parse_servers(storage *storage,  char *servers) {
  printf("IN PARSE SERVERS\n");
  char *tok_s;
  char *tok = strtok_r(servers, ",", &tok_s);
  
  while (tok != NULL) {
    // printf("IN LOOP -- %s\n", tok);
    parse_server(&storage->servers[storage->server_count], tok);
    storage->server_count++;
    tok = strtok_r(NULL, ",", &tok_s);
  }
  
  // printf("N servers -- %d\n", storage->server_count);
}


void
parse_config (info *storage_info, char *path)
{
  char *s, buff[BUFFLEN];
  FILE *fp = fopen (path, "r");
  // printf("%s\n", path);
  if (fp == NULL)
  {
    return;
  }
  // printf("SUCCES OPEN\n");
  /* Read next line */
  while ((s = fgets (buff, sizeof buff, fp)) != NULL)
  {
    /* Skip blank lines and comments */
    if (buff[0] == '\n' || buff[0] == '#')
      continue;

    /* Parse name/value pair from line */
    char name[MAXLEN], value[MAXLEN_VAL];
    s = strtok (buff, "=");
    printf("TOKEN -- %s\n", s);
    if (s==NULL)
      continue;
    else {
      strncpy (name, s, MAXLEN);
      *strchr (name, ' ') = '\0';
    }
    s = strtok (NULL, "=");
    if (s==NULL)
      continue;
    else
      strncpy (value, s, MAXLEN_VAL);
    trim (value);
    printf("NAME -- %s\n", name);
    printf("VALUE -- %s\n", value);
   
    if (strcmp(name, ERRORLOG) == 0) {
      strncpy (storage_info->errorlog, value, MAXLEN);
      // printf ("info errorlog --%s\n", storage_info->errorlog);
    } else if (strcmp(name, CACHE_SIZE) == 0) {
      strncpy (storage_info->cache_size, value, MAXLEN);
      // printf ("cache __ %s\n", storage_info->cache_size);
    } else if (strcmp(name, CACHE_REPLACEMENT) == 0) {
      strncpy (storage_info->cache_replacement, value, MAXLEN);
      // printf ("cche repl __ %s\n", storage_info->cache_replacement);
    } else if (strcmp(name, TIMEOUT) == 0) {
      storage_info->timeout = atoi(value);
      // printf ("timeout is -- %d\n", storage_info->timeout);
    } else if (strcmp(name, DISKNAME) == 0) {
      storage_info->storage_count++;
      int stor_num = storage_info->storage_count - 1;
      strncpy (storage_info->storages[stor_num].diskname, value, MAXLEN);
      // printf ("diskname -- %s\n", storage_info->storages[stor_num].diskname);
    } else if (strcmp(name, MOUNTPOINT) == 0) {
      int stor_num = storage_info->storage_count - 1;
      strncpy (storage_info->storages[stor_num].mountpoint, value, MAXLEN);
      // printf ("mount point -- %s\n", storage_info->storages[stor_num].mountpoint);
    } else if (strcmp(name, RAID) == 0) {
      int stor_num = storage_info->storage_count - 1;
      storage_info->storages[stor_num].raid = atoi(value);
      // printf ("raid -- %d\n", storage_info->storages[stor_num].raid);
    } else if (strcmp(name, SERVERS) == 0) {
      int stor_num = storage_info->storage_count - 1;
      storage *cur_storage = &storage_info->storages[stor_num];
      cur_storage->server_count = 0;
      parse_servers(cur_storage, value);
    } else if (strcmp(name, HOTSWAP) == 0) {
      int stor_num = storage_info->storage_count - 1;
      remote *hotswap = &storage_info->storages[stor_num].hotswap;
      parse_server(hotswap, value);
    } else {
      // printf("WARNING: %s/%s: Unknown name/value pair!\n", name, value);
    }
  }

  /* Close file */
  fclose (fp);
}
