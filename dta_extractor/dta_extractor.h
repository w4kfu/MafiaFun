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
    DWORD TotalSum;
    DWORD OffsetStart;
    DWORD OffsetEnd;
    BYTE Name[16];
};

struct dtaFile
{
    char *name;
    DWORD dwKey1;
    DWORD dwKey2;
};

struct FileEntry
{
    DWORD TotalSize; // Look like TotalSize and Block
    DWORD Unknow04;
    DWORD Unknow08;
    DWORD Unknow0C;
    DWORD FileSize;
    DWORD NbBlock;
    DWORD NameLength;
    DWORD Unknow1C;
};

BOOL check_signature(struct file *sFile);
void Decypher(DWORD *Buffer, DWORD SizeBuffer, DWORD dwKey1, DWORD dwKey2);
void HeaderInfo(struct file *sFile, struct dtaFile *Infodta);
void FileEntryInfo(struct file *sFile, struct FileEntry *entry, struct dtaFile *Infodta, DWORD dwOffset);
void TableEntryInfo(struct TableEntry *entry);
void TableInfo(struct file *sFile, struct dtaHeader *header, struct dtaFile *Infodta);
struct dtaFile* GetInfodtaFile(LPCTSTR lpFileName);
void hex_dump(void *data, int size);

#endif // __DTA_EXTRACTOR_H__
