#ifndef __parse__
#define __parse__

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include "info.h"
#include "config.h"


void parse_config (info *storage_info, char *path);


#endif