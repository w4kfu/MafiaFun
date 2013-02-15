#include "dta_extractor.h"

BOOL check_signature(struct file *sFile)
{
    if (*(DWORD*)sFile->bMap == 0x30445349)
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

void HeaderInfo(struct file *sFile)
{
    struct dtaHeader *hDTA = NULL;
    struct dtaHeader HeaderDecy;

    if (!sFile && sFile->bMap == NULL)
        return;
    hDTA = (struct dtaHeader*)(sFile->bMap + 4);
    memcpy(&HeaderDecy, hDTA, sizeof (struct dtaHeader));
    // a5.dta ['0x4f4bb0c6', '0xea340420L']
    Decypher((DWORD*)&HeaderDecy, 0x10, 0x4f4bb0c6 ^ 0x39475694, 0xea340420^ 0x34985762);
    printf("1 : %X\n", HeaderDecy.Unknow00);
    printf("2 : %X\n", HeaderDecy.Unknow04);
    printf("3 : %X\n", HeaderDecy.Unknow08);
    printf("4 : %X\n", HeaderDecy.Unknow0C);
}

int main(int argc, char *argv[])
{
    struct file sFile;

    if (argc != 2)
    {
        printf("Usage : %s <*.dta>\n", argv[0]);
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
    HeaderInfo(&sFile);
    clean_file(&sFile);
    return 0;
}
