#ifndef __FILE_H__
#define __FILE_H__

#include <stdio.h>

#ifdef WIN32

#include <windows.h>

struct file
{
    HANDLE  hFile;
    HANDLE  hMap;
    PBYTE   bMap;
};

#endif

#ifdef __unix__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

struct file
{
	int hFile;
	int hMap;
	char *bMap;
	struct stat sb;
};

#endif

int open_file(char *lpFileName, struct file *sFile);
int mapcreate_file(struct file *sFile);
int mapview_file(struct file *sFile);
int open_and_map(char *lpFileName, struct file *sFile);
void clean_file(struct file *sFile);
int save_buf(char *lpFileName, char *bBuf, int dwSizeBuf);

#endif // __FILE_H__

