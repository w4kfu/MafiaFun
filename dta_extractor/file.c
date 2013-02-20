#include "file.h"

int open_file(char *lpFileName, struct file *sFile)
{
    #ifdef WIN32
    sFile->hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (sFile->hFile == INVALID_HANDLE_VALUE)
        return 0;
    return 1;
    #endif
    sFile->hFile = open(lpFileName, O_RDONLY);
    if (sFile->hFile == -1)
	return 0;
    return 1;
}

#ifdef WIN32
int mapcreate_file(struct file *sFile)
{
    sFile->hMap = CreateFileMapping(sFile->hFile, NULL, PAGE_READONLY, 0, 0, 0);
    if (sFile->hMap == NULL)
        return 0;
    return 1;
}
#endif

int mapview_file(struct file *sFile)
{
    #ifdef WIN32
    sFile->bMap = (PBYTE)MapViewOfFile(sFile->hMap, FILE_MAP_READ, 0, 0, 0);
    if (sFile->hMap == NULL)
        return 0;
    #endif
    if ((sFile->bMap = mmap (NULL, sFile->sb.st_size, PROT_READ, MAP_PRIVATE,
		       sFile->hFile, 0)) == MAP_FAILED)
	return 0;
    return 1;
    
}

int open_and_map(char *lpFileName, struct file *sFile)
{
    if (open_file(lpFileName, sFile) == 0)
        return 0;
    #ifdef WIN32
    if (mapcreate_file(sFile) == 0)
        return 0;
    #endif
    if (mapview_file(sFile) == 0)
        return 0;
    return 1;
}

void clean_file(struct file *sFile)
{
    /*CloseHandle(sFile->hFile);
    CloseHandle(sFile->hMap);
    UnmapViewOfFile(sFile->bMap);*/
}

int save_buf(char *lpFileName, char *bBuf, int dwSizeBuf)
{
    /*HANDLE hFile;
    DWORD dwByteWritten;

    if ((hFile = CreateFileA(lpFileName,(GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(hFile, bBuf, dwSizeBuf, &dwByteWritten, NULL);
    if (dwByteWritten != dwSizeBuf)
    {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;*/
}


