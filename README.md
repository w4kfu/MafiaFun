# MafiaFun

This repository contains different toolz for having fun with the game Mafia

## Files

### extract_key.py

Idapython script for extracting key required for decyphering .dta files

### dta_extractor

Known Issues : some .dta files are not correctly handle. 

Program for extracting .dta files, only work with few of them, tested on AB.dta to get all the music files (.ogg) :

* SOUNDS\MUSIC\05 - Calm.ogg
* SOUNDS\MUSIC\03 - Fate.ogg
* SOUNDS\MUSIC\14 - Success.ogg
* SOUNDS\MUSIC\Lake of Fire.ogg
* SOUNDS\MUSIC\mise02-ulicka.ogg
* SOUNDS\MUSIC\city_music_01.ogg
* SOUNDS\MUSIC\city_music_10.ogg
* SOUNDS\MUSIC\city_music_02.ogg
* SOUNDS\MUSIC\city_music_11.ogg
* SOUNDS\MUSIC\city_music_03.ogg
* SOUNDS\MUSIC\city_music_12.ogg
* SOUNDS\MUSIC\city_music_04.ogg
* SOUNDS\MUSIC\city_music_13.ogg
* SOUNDS\MUSIC\city_music_05.ogg
* SOUNDS\MUSIC\city_music_06.ogg
* SOUNDS\MUSIC\city_music_15.ogg
* SOUNDS\MUSIC\city_music_07.ogg
* SOUNDS\MUSIC\city_music_08.ogg
* SOUNDS\MUSIC\city_music_09.ogg
* SOUNDS\MUSIC\13 - Game Over.ogg
* SOUNDS\MUSIC\12_scene music.ogg
* SOUNDS\MUSIC\20 - Carchase 2.ogg
* SOUNDS\MUSIC\19 - Carchase 1.ogg
* SOUNDS\MUSIC\01 - Main Theme.ogg
* SOUNDS\MUSIC\15 - Surprise 1.ogg
* SOUNDS\MUSIC\16 - Surprise 2.ogg
* SOUNDS\MUSIC\18 - Escalation.ogg
* SOUNDS\MUSIC\17 - Saras Theme.ogg
* SOUNDS\MUSIC\11 - Night Psycho.ogg
* SOUNDS\MUSIC\06 - Briefing - Bad.ogg
* SOUNDS\MUSIC\08 - Briefing - Good.ogg
* SOUNDS\MUSIC\10 - Fighting theme 2.ogg
* SOUNDS\MUSIC\09 - Fighting theme 1.ogg
* SOUNDS\MUSIC\04 - Sorrow and Church.ogg
* SOUNDS\MUSIC\12 - Quiet Before Storm.ogg
* SOUNDS\MUSIC\07 - Briefing - Conspiracy.ogg
* SOUNDS\MUSIC\02 - Main Theme (short version).ogg

### craft_dta.py

Exploit a stackoverflow in rw_data.dll

The vulnerability is in function called by :

	003618A0 ; int __stdcall dtaOpen(LPCSTR lpFileName, char)
	
function sub_361B90 have an array of char on the : 

	00361B90 var_208= byte ptr -208h
	
When they read the "real name" of the file, they don't check the size to read (or only the & 0x7FFF) :

	.text:00361E3F push    0               ; lpOverlapped
	.text:00361E41 and     edx, 7FFFh
	.text:00361E47 push    ecx             ; lpNumberOfBytesRead
	.text:00361E48 push    edx             ; nNumberOfBytesToRead
	.text:00361E49 mov     edx, [esi+eax]
	.text:00361E4C lea     ecx, [esp+2E8h+var_208]
	.text:00361E53 push    ecx             ; lpBuffer
	.text:00361E54 push    edx             ; hFile
	.text:00361E55 call    ebx ; ReadFile
	
Watch the extractor of .dta file for understand how the file format work.