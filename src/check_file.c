#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <gcrypt.h>
#include "polwatch.h"

int check_file(const char *file_path, const char *file_md5, const char *file_sha256){
	int fd;
	fd = open(file_path, O_RDONLY | O_NOFOLLOW);
	if(fd == -1 && errno == ENOENT){
		printf("%s -> %s\n", file_path, strerror(errno));
		return -1;
	}
	if(fd == -1 && errno == EACCES){
		printf("%s -> %s\n", file_path, strerror(errno));
		return -1;
	}
	check_hash(fd, file_md5, file_sha256);
	return 0;
}
