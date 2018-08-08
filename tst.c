#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "info.h"
#include "config.h"
#include "tst.h"

#define PATH "tst.log"

static void print_server(FILE *fp, remote *server) {
	fprintf(fp, "%s", server->ip_address);
	fprintf(fp, ":");
	fprintf(fp, "%s", server->port);
}


static void print_servers(FILE *fp, storage *stor) {
	int i = 0;
	fprintf(fp, "%s = ", SERVERS);
	for (; i < stor->server_count; ++i) {
		print_server(fp, &stor->servers[i]);
		if ((i+1) != stor->server_count) {
			fprintf(fp, ", ");
		}
	}
	fprintf(fp, "\n");
}

static void print_storage(FILE *fp, storage *stor) {
	char buff[128];
	fprintf(fp, "%s = %s\n", DISKNAME, stor->diskname);
	fprintf(fp, "%s = %s\n", MOUNTPOINT, stor->mountpoint);
	sprintf(buff, "%d", stor->raid);
	fprintf(fp, "%s = %s\n", RAID, buff);
	print_servers(fp, stor);
	fprintf(fp, "%s = ", HOTSWAP);
	print_server(fp, &stor->hotswap);
	fprintf(fp, "\n");
}



void test_storage(strg_info_t *strg_info) {
		// printf("errorlog name -- %s\n", strg_info->errorlog);
	char buff[128];
	// printf("%s\n", strg_info->errorlog);
	FILE *fp = fopen (PATH, "a");
	fprintf(fp, "Initialize Logging.....\n");
	fprintf(fp, "Logging config.....\n");
	

	fprintf(fp, "%s = %s\n", ERRORLOG, strg_info->errorlog);
	fprintf(fp, "%s = %s\n", CACHE_SIZE, strg_info->cache_size);
	fprintf(fp, "%s = %s\n", CACHE_REPLACEMENT, strg_info->cache_replacement);

	sprintf(buff, "%d", strg_info->timeout);
	fprintf(fp, "%s = %s\n", TIMEOUT, buff);

	print_storage(fp, &strg_info->strg);

	fclose(fp);
}