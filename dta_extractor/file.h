#ifndef __FILE_H__
#define __FILE_H__

#include <stdio.h>
#include <windows.h>

struct file
{
    HANDLE  hFile;
    HANDLE  hMap;
    PBYTE   bMap;
};

BOOL open_file(LPCTSTR lpFileName, struct file *sFile);
BOOL mapcreate_file(struct file *sFile);
BOOL mapview_file(struct file *sFile);
BOOL open_and_map(LPCTSTR lpFileName, struct file *sFile);
void clean_file(struct file *sFile);
BOOL save_buf(LPCTSTR lpFileName, PBYTE bBuf, DWORD dwSizeBuf);

#endif // __FILE_H__

