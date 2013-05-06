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

#define GCRYPT_VER "1.5.0"

int main(void){
	if(!gcry_check_version(GCRYPT_VER)){
		fputs("libgcrypt version mismatch\n", stderr);
		exit(2);
	}
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	sqlite3 *conn;
    	sqlite3_stmt *res;
    	int error = 0;
    	int retval, col, cols;
    	const char *tail;

	error = sqlite3_open("test.db", &conn);
	if(error != SQLITE_OK) abort();
	error = sqlite3_prepare_v2(conn, "select * from info", 25, &res, &tail);
	if(error != SQLITE_OK) abort();
	cols = sqlite3_column_count(res);

	while(1){
		retval = sqlite3_step(res);

		if(retval == SQLITE_ROW){
			for(col=0 ; col<cols;){
				const char *path = (const char*)sqlite3_column_text(res,col);
				++col;
				const char *md5 = (const char*)sqlite3_column_text(res,col);
				++col;
				const char *sha256 = (const char *)sqlite3_column_text(res,col);
				check_file(path, md5, sha256);
				++col;
			}
		}
		else if(retval == SQLITE_DONE){
			printf("All rows fetched\n");
			break;
		}
		else{
			printf("Some error encountered\n");
			return -1;
		}
	}
	sqlite3_finalize(res);
    	sqlite3_close(conn);
	return 0;
}
