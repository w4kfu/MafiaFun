#include "dta_extractor.h"

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
            sprintf_s(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
        c = *p;
        if (isalnum(c) == 0)
		{
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
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

BOOL check_signature(struct file *sFile)
{
    if (*(DWORD*)sFile->bMap == 0x30445349) // 'ISD0'
        return TRUE;
    return FALSE;
}

void Decypher(DWORD *Buffer, DWORD SizeBuffer, DWORD dwKey1, DWORD dwKey2)
{
    DWORD i;

	for (i = 0; i < SizeBuffer / 4; i += 2)
	{
		Buffer[i] = ~(~Buffer[i] ^ dwKey1);
		Buffer[i + 1] = ~(~Buffer[i + 1] ^ dwKey2);
	}
	for (i = 0; i < SizeBuffer % 8; i++)
	{
        printf("REMAINING TO FIX\n");
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
    Decypher((DWORD*)&HeaderDecy, 0x10, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
    printf("NbEntry : %X\n", HeaderDecy.NbEntry);
    printf("OffsetTable : %X\n", HeaderDecy.OffsetTable);
    printf("SizeTable : %X\n", HeaderDecy.SizeTable);
    printf("Unknow0C : %X\n", HeaderDecy.Unknow0C);
    TableInfo(sFile, &HeaderDecy, Infodta);
}

void TableEntryInfo(struct TableEntry *entry)
{
    BYTE Name[17] = {0};

    printf("Unknow00 : %X\n", entry->Unknow00);
    printf("Unknow04 : %X\n", entry->Unknow04);
    printf("Unknow08 : %X\n", entry->Unknow08);
    // Some entry don't finish with \x00
    strncpy(Name, entry->Name, 16);
    printf("Name : %s\n", Name);
}

void TableInfo(struct file *sFile, struct dtaHeader *header, struct dtaFile *Infodta)
{
    BYTE *Table = NULL;

    printf("NB ENTRY = %X\n", header->SizeTable / sizeof (struct TableEntry));
    Table = malloc(sizeof (char) * header->SizeTable);
    if (!Table)
        return;
    memcpy(Table, sFile->bMap + header->OffsetTable, header->SizeTable);
    Decypher(Table, header->SizeTable, Infodta->dwKey1 ^ 0x39475694, Infodta->dwKey2 ^ 0x34985762);
    hex_dump(Table, header->SizeTable);
    TableEntryInfo(Table);
    TableEntryInfo(Table + sizeof (struct TableEntry));
    TableEntryInfo(Table + sizeof (struct TableEntry) * 2);
    TableEntryInfo(Table + sizeof (struct TableEntry) * 3);
}

struct dtaFile* GetInfodtaFile(LPCTSTR lpFileName)
{
    DWORD i;

    for (i = 0; i < sizeof (dtaFiles); i++)
    {
        if (!strcmpi(dtaFiles[i].name, lpFileName))
            return &dtaFiles[i];
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
    if (open_and_map(argv[1], &sFile) == FALSE)
    {
        clean_file(&sFile);
        printf("[-] open_and_map failed\n", 0);
        return 1;
    }
    if (check_signature(&sFile) == FALSE)
    {
        clean_file(&sFile);
        printf("[-] It's not a valid .dta file\n", 0);
        return 1;
    }
    HeaderInfo(&sFile, Infodta);
    clean_file(&sFile);
    return 0;
}
