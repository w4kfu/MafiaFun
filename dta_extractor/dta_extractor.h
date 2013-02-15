#ifndef __DTA_EXTRACTOR_H__
#define __DTA_EXTRACTOR_H__

# include "file.h"

struct dtaHeader
{
    DWORD Unknow00;
    DWORD Unknow04;
    DWORD Unknow08;
    DWORD Unknow0C;
};

BOOL check_signature(struct file *sFile);
void HeaderInfo(struct file *sFile);
void Decypher(DWORD *Buffer, DWORD SizeBuffer, DWORD dwKey1, DWORD dwKey2);

#endif // __DTA_EXTRACTOR_H__
