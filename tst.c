#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "info.h"
#include "config.h"


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

void test(info *storage_info) {
	// printf("errorlog name -- %s\n", storage_info->errorlog);
	char buff[128];
	FILE *fp = fopen (storage_info->errorlog, "w");
	// fprintf(fp, "Initialize Logging.....\n");
	// fprintf(fp, "Logging config.....\n");

	fprintf(fp, "%s = %s\n", ERRORLOG, storage_info->errorlog);
	fprintf(fp, "%s = %s\n", CACHE_SIZE, storage_info->cache_size);
	fprintf(fp, "%s = %s\n", CACHE_REPLACEMENT, storage_info->cache_replacement);

	sprintf(buff, "%d", storage_info->timeout);
	fprintf(fp, "%s = %s\n", TIMEOUT, buff);

	int n_storages = storage_info->storage_count;
	int i = 0;
	for (; i < n_storages; ++i) {
		print_storage(fp, &storage_info->storages[i]);
	}

	fclose(fp);
}
