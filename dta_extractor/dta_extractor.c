#include "dta_extractor.h"

struct dtaFile dtaFiles[12] =
{
    {"a2.dta", 0x1417d340, 0xb6399e19},
    {"a6.dta",0x728e2db9, 0x5055da68},
    {"a0.dta",0x7f3d9b74, 0xec48fe17},
    {"a1.dta",0xe7375f59, 0x900210e},
    {"a3.dta",0xa94b8d3c, 0x771f3888},
    {"ac.dta",0xa94b8d3c, 0x771f3888},
    {"a4.dta",0xa94b8d3c, 0x771f3888},
    {"aa.dta",0xd4ad90c6, 0x67da216e},
    {"a5.dta",0x4f4bb0c6, 0xea340420},
    {"a7.dta",0xf4f03a72, 0xe266fe62},
    {"a9.dta",0x959d1117, 0x5b763446},
    {"ab.dta",0x7f3d9b74, 0xec48fe17},
};

int check_signature(struct file *sFile)
{
    if (*(unsigned int*)sFile->bMap == 0x30445349) // 'ISD0'
        return 1;
    return 0;
}

void Decypher(unsigned int *Buffer, int SizeBuffer, unsigned int dwKey1, unsigned int dwKey2)
{
    int i;
    unsigned int key[2] = {dwKey1, dwKey2};
    unsigned char *pkey = (unsigned char*)key;
    unsigned char *pBuf;

    pBuf = (unsigned char*)Buffer;
    for (i = 0; i < SizeBuffer / 8; i++)
    {
	*Buffer = ~(~*Buffer ^ dwKey1);
	Buffer++;
	*Buffer = ~(~*Buffer ^ dwKey2);
	Buffer++;
	pBuf += 8;
    }
    /*for (i = 0; i < SizeBuffer / 8; i += 2)
    {
        Buffer[i] = ~(~Buffer[i] ^ dwKey1);
        Buffer[i + 1] = ~(~Buffer[i + 1] ^ dwKey2);
        pBuf += 8;
    }*/
    for (i = 0; i < SizeBuffer % 8; i++)
    {
        *pBuf = ~(~(*pBuf) ^ *pkey++);
        pBuf++;
    }
}

void HeaderInfo(struct file *sFile, struct dtaFile *Infodta)
{
    struct dtaHeader *hDTA = NULL;
    struct dtaHeader HeaderDecy;

    if (!sFile && sFile->bMap == NULL)
        return;
    hDTA = (struct dtaHeader*)(sFile->bMap + 4);
    memcpy(&HeaderDecy, hDTA, sizeof (struct dtaHeader));
    Decypher((unsigned int*)&HeaderDecy, 0x10, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
    printf("NbEntry : %X\n", HeaderDecy.NbEntry);
    printf("OffsetTable : %X\n", HeaderDecy.OffsetTable);
    printf("SizeTable : %X\n", HeaderDecy.SizeTable);
    printf("Unknow0C : %X\n", HeaderDecy.Unknow0C);
    TableInfo(sFile, &HeaderDecy, Infodta);
}

void FileEntryInfo(struct file *sFile, struct FileEntry *entry, struct dtaFile *Infodta, int dwOffset)
{
    char *name;
    unsigned int dwNameLength;
    char *savefile = NULL;
    char *spbuf = NULL;
    char lulz[0x9001];
    unsigned int i;

    printf("TotalSize : %X\n", entry->TotalSize);
    printf("Unknow04 : %X\n", entry->Unknow04);
    printf("Unknow08 : %X\n", entry->Unknow08);
    printf("Unknow0C : %X\n", entry->Unknow0C);
    printf("FileSize : %X\n", entry->FileSize);
    printf("NbBlock : %X\n", entry->NbBlock);
    printf("NameLength : %X\n", entry->NameLength & 0x7FFF);
    printf("Unknow1C : %X\n", entry->Unknow1C);

    dwNameLength = entry->NameLength & 0x7FFF;
    name = xalloc(sizeof (char) * (dwNameLength + 1));
    if (!name)
        return;
    memcpy(name, sFile->bMap + dwOffset + 0x20, dwNameLength);
    Decypher((unsigned int*)name, dwNameLength, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
    name[dwNameLength] = 0;
    printf("Name = %s\n", name);
    savefile = xalloc(sizeof (char) * entry->FileSize);
    if (!savefile)
        return;

    /* SRSLY !? */
    spbuf = savefile;
    for (i = 0; i < entry->FileSize / 0x8000; i++)
    {
        memcpy(lulz, sFile->bMap + dwOffset + 0x20 + dwNameLength + 4 + i * 0x8005, 0x8001);
        Decypher((unsigned int*)lulz, 0x8001, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
        memcpy(savefile, lulz + 1, 0x8000);
        savefile += 0x8000;
    }
    if (entry->FileSize % 0x8000)
    {
        memcpy(lulz, sFile->bMap + dwOffset + 0x20 + dwNameLength + 4 + (entry->FileSize / 0x8000) * 0x8005, (entry->FileSize % 0x8000) + 1);
        Decypher((unsigned int*)lulz, (entry->FileSize % 0x8000) + 1, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
        memcpy(savefile, lulz + 1, entry->FileSize % 0x8000);
    }
    /*if (strrchr(name, '\\'))
    {
        save_buf(strrchr(name, '\\') + 1, spbuf, entry->FileSize);
    }*/
    xfree(name);
    xfree(spbuf);
}

void TableEntryInfo(struct TableEntry *entry)
{
    char Name[17] = {0};

    printf("TotalSum : %X\n", entry->TotalSum);
    printf("OffsetStart : %X\n", entry->OffsetStart);
    printf("OffsetEnd : %X\n", entry->OffsetEnd);
    // Some entry don't finish with \x00
    strncpy(Name, entry->Name, 16);
    printf("Name : %s\n", Name);
}

void TableInfo(struct file *sFile, struct dtaHeader *header, struct dtaFile *Infodta)
{
    struct TableEntry *Table = NULL;
    struct FileEntry fentry;
    unsigned int i;

    printf("NB ENTRY = %X\n", header->SizeTable / sizeof (struct TableEntry));
    //Table = VirtualAlloc(NULL, sizeof (char) * header->SizeTable, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Table = xalloc(sizeof (char) * header->SizeTable);
    if (!Table)
        return;
    memcpy(Table, sFile->bMap + header->OffsetTable, header->SizeTable);
    Decypher((unsigned int*)Table, header->SizeTable, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
    //hex_dump(Table, header->SizeTable);
    for (i = 0; i < header->SizeTable / sizeof (struct TableEntry); i++)
    {
        TableEntryInfo(&Table[i]);
        memcpy(&fentry, sFile->bMap + Table[i].OffsetStart, sizeof (struct FileEntry));
        Decypher((unsigned int*)&fentry, sizeof (struct FileEntry), Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
        FileEntryInfo(sFile, &fentry, Infodta, Table[i].OffsetStart);
    }
    xfree(Table);
    //VirtualFree(Table, 0, MEM_RELEASE);
}

struct dtaFile* GetInfodtaFile(char *lpFileName)
{
    unsigned int i;

    for (i = 0; i < sizeof (dtaFiles) / sizeof (struct dtaFile); i++)
    {

	#ifdef WIN32

        if (!strcmpi(dtaFiles[i].name, lpFileName))
            return &dtaFiles[i];

	#endif

	#ifdef __unix__

        if (!strcasecmp(dtaFiles[i].name, lpFileName))
            return &dtaFiles[i];

	#endif
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    struct file sFile;
    struct dtaFile *Infodta = NULL;

    if (argc != 2)
    {
        printf("Usage : %s <*.dta>\n", argv[0]);
        return 1;
    }
    Infodta = GetInfodtaFile(argv[1]);
    if (!Infodta)
    {
        printf("Can't get info for this dta file\n");
        return 1;
    }
    if (open_and_map(argv[1], &sFile) == 0)
    {
        clean_file(&sFile);
        printf("[-] open_and_map failed\n");
        return 1;
    }
    if (check_signature(&sFile) == 0)
    {
        clean_file(&sFile);
        printf("[-] It's not a valid .dta file\n");
        return 1;
    }
    HeaderInfo(&sFile, Infodta);
    clean_file(&sFile);
    return 0;
}

void hex_dump(void *data, int size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for(n = 1; n <= size; n++)
    {
        if (n % 16 == 1)
        {
            snprintf(addrstr, sizeof(addrstr), "%.4x",
                ((unsigned int)p-(unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0)
        {
            c = '.';
        }
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);
        if (n % 16 == 0)
        {
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0)
        {
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }
    if (strlen(hexstr) > 0)
    {
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

void *xalloc(size_t size)
{
	#ifdef WIN32

    	return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	#endif

	#ifdef __unix__

	return malloc(size);

	#endif
	
}

void xfree(void *ptr)
{
	#ifdef WIN32

    	VirtualFree(ptr, 0, MEM_RELEASE);

	#endif

	#ifdef __unix__

	free(ptr);

	#endif
}
