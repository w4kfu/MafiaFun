#ifndef __DTA_EXTRACTOR_H__
#define __DTA_EXTRACTOR_H__

# include "file.h"

#ifdef __unix__

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#endif


struct dtaHeader
{
    unsigned int NbEntry;
    unsigned int OffsetTable;
    unsigned int SizeTable;
    unsigned int Unknow0C;
};

struct TableEntry
{
    unsigned int TotalSum;
    unsigned int OffsetStart;
    unsigned int OffsetEnd;
    char Name[16];
};

struct dtaFile
{
    char *name;
    unsigned int dwKey1;
    unsigned int dwKey2;
};

struct FileEntry
{
    unsigned int TotalSize; // Look like TotalSize and Block
    unsigned int Unknow04;
    unsigned int Unknow08;
    unsigned int Unknow0C;
    unsigned int FileSize;
    unsigned int NbBlock;
    unsigned int NameLength;
    unsigned int Unknow1C;
};

int check_signature(struct file *sFile);
void Decypher(unsigned int *Buffer, int SizeBuffer, unsigned int dwKey1, unsigned int dwKey2);
void HeaderInfo(struct file *sFile, struct dtaFile *Infodta);
void FileEntryInfo(struct file *sFile, struct FileEntry *entry, struct dtaFile *Infodta, int dwOffset);
void TableEntryInfo(struct TableEntry *entry);
void TableInfo(struct file *sFile, struct dtaHeader *header, struct dtaFile *Infodta);
struct dtaFile* GetInfodtaFile(char *lpFileName);
void hex_dump(void *data, int size);
void *xalloc(size_t size);
void xfree(void *ptr);

#endif // __DTA_EXTRACTOR_H__
