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

int check_hash(int fd_no, const char *f_md5, const char *f_sha256){
	int md5algo, sha256algo, i;
	char hashed_md5[33], hashed_sha256[65];
	struct stat fileStat;
	char *buffer;
	const char *md5name = gcry_md_algo_name(GCRY_MD_MD5);
	const char *sha256name = gcry_md_algo_name(GCRY_MD_SHA256);
	md5algo = gcry_md_map_name(md5name);
	sha256algo = gcry_md_map_name(sha256name);
	off_t fsize = 0, donesize = 0, diff = 0;
  	if(fstat(fd_no, &fileStat) < 0){
  		perror("Fstat error");
    	return -1;
  	}
  	fsize = fileStat.st_size;
  	FILE *fp = fdopen(fd_no, "r");
  	if(fp == NULL){
  		printf("Cannot open file for read\n");
  		return -1;
  	}
	gcry_md_hd_t hd_md5;
	gcry_md_hd_t hd_sha256;
	gcry_md_open(&hd_md5, md5algo, 0);
	gcry_md_open(&hd_sha256, sha256algo, 0);
	if(fsize < 10024){
		buffer = malloc(fsize);
  		if(buffer == NULL){
  			printf("malloc error\n");
  			return -1;
  		}
		fread(buffer, 1, fsize, fp);
		gcry_md_write(hd_md5, buffer, fsize);
		gcry_md_write(hd_sha256, buffer, fsize);
		goto nowhile;
	}
	buffer = malloc(10024);
  	if(buffer == NULL){
  		printf("malloc error\n");
  		return -1;
  	}
	while(fsize > donesize){
		fread(buffer, 1, 10024, fp);
		gcry_md_write(hd_md5, buffer, 10024);
		gcry_md_write(hd_sha256, buffer, 10024);
		donesize+=10024;
		diff=fsize-donesize;
		if(diff < 10024){
			fread(buffer, 1, diff, fp);
			gcry_md_write(hd_md5, buffer, diff);
			gcry_md_write(hd_sha256, buffer, diff);
			break;
		}
	}
	nowhile:
	gcry_md_final(hd_md5);
	gcry_md_final(hd_sha256);
	unsigned const char *md5 = gcry_md_read(hd_md5, md5algo);
	unsigned const char *sha256 = gcry_md_read(hd_sha256, sha256algo);
 	for(i=0; i<16; i++){
 		sprintf(hashed_md5+(i*2), "%02x", md5[i]);
 	}
 	for(i=0; i<32; i++){
 		sprintf(hashed_sha256+(i*2), "%02x", sha256[i]);
 	}
 	hashed_md5[32] = '\0';
 	hashed_sha256[64] = '\0';
 	free(buffer);
 	fclose(fp);
 	close(fd_no);
 	if((strcmp(f_md5, hashed_md5) != 0) || (strcmp(f_sha256, hashed_sha256) != 0)){
 		printf("Error: checksum mismatch\n");
 	}
 	else printf("Checksum ok\n");
	gcry_md_close(hd_md5);
	gcry_md_close(hd_sha256);
	return 0;
}
