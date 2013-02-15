#ifndef __DTA_EXTRACTOR_H__
#define __DTA_EXTRACTOR_H__

# include "file.h"

struct dtaHeader
{
    DWORD NbEntry;
    DWORD OffsetTable;
    DWORD SizeTable;
    DWORD Unknow0C;
};

struct TableEntry
{
    DWORD Unknow00;
    DWORD Unknow04;
    DWORD Unknow08;
    BYTE Name[16];
};

struct dtaFile
{
    char *name;
    DWORD dwKey1;
    DWORD dwKey2;
};

BOOL check_signature(struct file *sFile);
void HeaderInfo(struct file *sFile, struct dtaFile *Infodta);
void Decypher(DWORD *Buffer, DWORD SizeBuffer, DWORD dwKey1, DWORD dwKey2);
void TableInfo(struct file *sFile, struct dtaHeader *header, struct dtaFile *Infodta);

#endif // __DTA_EXTRACTOR_H__
