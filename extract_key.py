from idaapi import *
from idc import *

def getnamefile(ref):
	codepush = FindCode(ref, SEARCH_UP)
	if GetMnem(codepush) == "push":
		addrStr = GetOperandValue(codepush, 0)
		if addrStr != 0:
			filename = GetString(addrStr, -1, ASCSTR_C)
			return filename
	return None

def getCdtaptr(ref):
	codemov = FindCode(ref, SEARCH_DOWN)
	if GetMnem(codemov) == "mov":
		Cdta = GetOperandValue(codemov, 0)
		return Cdta
	return None
	
def getkey(refCdta):
	for ref in DataRefsTo(refCdta):
		if GetMnem(ref) == "mov" and GetOpnd(ref, 0) == "ecx":
			next_instruction = ref
			while next_instruction != BADADDR:
				next_instruction = FindCode(next_instruction, SEARCH_DOWN)
				if GetMnem(next_instruction) == "push":
					key_2 = GetOperandValue(next_instruction, 0)
					next_instruction = FindCode(next_instruction, SEARCH_DOWN)
					if GetMnem(next_instruction) != "push":
						return None # WTF
					key_1 = GetOperandValue(next_instruction, 0)
					return (key_1, key_2)
	return None

def extract_key():
	ea_create = LocByName("_dtaCreate@4")
	if ea_create != 0:
		for ref in CodeRefsTo(ea_create, 0):
			filename = getnamefile(ref)
			if filename != None:
				Cdta = getCdtaptr(ref)
				if Cdta != None:
					keys = getkey(Cdta)
					print filename, map(hex, keys)
	else:
		print "[-] Can't find _dtaCreate@4 import"
		
def main():
	extract_key()
	
if __name__ == '__main__':
	main() 