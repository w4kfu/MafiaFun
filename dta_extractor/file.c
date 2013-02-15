#include "file.h"

BOOL open_file(LPCTSTR lpFileName, struct file *sFile)
{
    sFile->hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (sFile->hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    return TRUE;
}

BOOL mapcreate_file(struct file *sFile)
{
    sFile->hMap = CreateFileMapping(sFile->hFile, NULL, PAGE_READONLY, 0, 0, 0);
    if (sFile->hMap == NULL)
        return FALSE;
    return TRUE;
}

BOOL mapview_file(struct file *sFile)
{
    sFile->bMap = (PBYTE)MapViewOfFile(sFile->hMap, FILE_MAP_READ, 0, 0, 0);
    if (sFile->hMap == NULL)
        return FALSE;
    return TRUE;
}

BOOL open_and_map(LPCTSTR lpFileName, struct file *sFile)
{
    if (open_file(lpFileName, sFile) == FALSE)
        return FALSE;
    if (mapcreate_file(sFile) == FALSE)
        return FALSE;
    if (mapview_file(sFile) == FALSE)
        return FALSE;
    return TRUE;
}

void clean_file(struct file *sFile)
{
    CloseHandle(sFile->hFile);
    CloseHandle(sFile->hMap);
    CloseHandle(sFile->bMap);
}

BOOL save_buf(LPCTSTR lpFileName, PBYTE bBuf, DWORD dwSizeBuf)
{
    HANDLE hFile;
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
    return TRUE;
}


