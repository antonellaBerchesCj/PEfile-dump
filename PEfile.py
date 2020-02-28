import sys
import getopt
import pydasm
import pefile
import struct

#------------------------------------------------------------------------
# command line: python.exe filename.py -d/h/i/e/t filename.exe
#------------------------------------------------------------------------

# Get BYTE from byte array
def byte(data, offset):
	return struct.unpack('<B', data[offset:offset+1])[0]

# Get WORD from byte array
def word(data, offset):
    return data[offset] + (data[offset+1]<<8)

# Get DWORD from byte array (file input)
def dword(data, offset):
	return struct.unpack('<I', data[offset:offset+4])[0]

def qword(data, offset):
	return struct.unpack('<Q', data[offset:offset+8])[0]

# The string starts at given offset. If the length is negative, the function reads the first NULL character.
# If you specify max. length the function stops on the first NULL character
# if specified number of characters have been retrieved whatever comes first.
def getStringFromByteArray(data, offset, length = -1):
    name = ""
    if (length>=0):
        for j in range(offset, offset+length):
            if data[j] == 0:
                break;
            name = name + chr(data[j])
    else:
        ch = data[offset]
        while ch != 0:
            name = name + chr(ch)
            offset = offset + 1
            ch = data[offset]
    return name

def convertRVAtoOffset(sections, rva):
	for s in sections:
		if rva >= s[1] and rva < s[1] + s[2]:
			offset = rva - s[1] + s[3]
			return offset
	raise ValueError ("Invalid RVA %x" % rva)
	#return False

def find_ep_section(pe, ep_rva): #check whether the section contains the address
    for section in pe.sections:
        if section.contains_rva(ep_rva):
            return section
    return None

def display_instruction(file_path):
	pe = pefile.PE(file_path)

	fd = open(file_path, 'rb')
	data = fd.read()
	s = fd.read(4).decode(encoding="utf-8", errors="strict")
	if "MZ" in s:
		print "Not an EXE file"
	else:
		print "EXE file (contains MZ string)"
	fd.close()

	for section in pe.sections:
		if((pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress) and (pe.OPTIONAL_HEADER.AddressOfEntryPoint < (section.VirtualAddress + section.Misc_VirtualSize))):
			print "AddressOfEntryPoint (offset): %x" % pe.OPTIONAL_HEADER.AddressOfEntryPoint #this is VA

	print "ImageBase: %x" % pe.OPTIONAL_HEADER.ImageBase

	# search in which section header this VA resides
	for section in pe.sections:
		if((pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress) and ((pe.OPTIONAL_HEADER.AddressOfEntryPoint -  section.VirtualAddress) <  section.Misc_VirtualSize)):
			print "VA is inside the section: ", (section.Name)

	ep_va = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase #EP VA

	#Entry Point is the first executed byte in the PE file - preluare nr sectiunii in care se afla entry point-ul
	offset = pe.OPTIONAL_HEADER.AddressOfEntryPoint #offset -> entrypoint

	dir_export = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
	print "dir_export: %x " % dir_export

	dir_import = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
	print "dir_import: %x " % dir_import

	code_section = find_ep_section(pe, offset)
	if not code_section:
		return

	#Start disassembly at the EP: pentru a extrage instructiuni se porneste de la PointerToRawData (File Pointer catre datele RAW)
	print("Entry point is at offset: {:#x}".format(code_section.PointerToRawData))

	# get first 10 bytes at entry point and dump them
	code_at_ep = code_section.get_data(offset, 10)
	print("\nCode at offset [%x]: {}\n".format(" ".join("{:02x}".format(ord(c)) for c in code_at_ep))) % pe.OPTIONAL_HEADER.AddressOfEntryPoint

	print "\n\tInstructions: "
	# print 10 instructions:
	for i in code_at_ep:
		i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
		instructiuns = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset)
		print instructiuns
		try:
			f = open("Instructions.txt", "a")
			f.write(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset))
			f.write('\n')
		except:
			pass
		if not i:
			break
		# Go to the next instruction
		offset += i.length
	return True

def display_headers(file_path, data, sections, e_lfanew, nrSections, addressOfEntryPoint, optionalHeader_Magic, optionalHeaderSize, exportDirectoryRVA, exportDirectorySize, importDirectoryRVA, importDirectorySize, TLSrvaAddress, TLSDirectorySize):
	print ("\tFile: %s, size: %s (%x)" % (file_path, len(data), len(data)))

	# DOS HEADER - magic number
	if word(data, 0) != 0x5A4D: # MZ
		print(file_path + " - The file is not a MZ file")
		return False

	# Read NT HEADER
	print "-----------------------DOS HEADER---------------------------"
	e_magic = word(data, 0)
	print "e_magic: %x" % e_magic
	print "e_lfanew: %06x\n" % e_lfanew

	ntHeader = e_lfanew
	ntSignature = dword(data, ntHeader)

	if ntSignature != 0x4550: # PE00
		print(file_path + " - Is NOT a PE file")
	else:
		print(file_path + " - Is a PE file")

	# Read FILE HEADER
	print "----------------------FILE HEADER---------------------------"
	characteristics = word(data, ntHeader + 22)

	if optionalHeader_Magic == 0x20b:
		print("\tThe file %s is a 64-bit executable." % file_path)
	elif optionalHeader_Magic == 0x10b:
		print("\tThe file %s is a 32-bit executable." % file_path)

	print ("Nr. Sections: \t\t\t%x" % nrSections)
	print ("Optional Header Size: \t\t%x" % optionalHeaderSize)
	print ("Characteristics:\t\t%x" % characteristics)

	# Read OPTIONAL HEADER
	print "------------------OPTIONAL HEADER---------------------------"
	if optionalHeader_Magic == 0x20b: # 64bit
		imageBase = qword(data, ntHeader + 48)
		print("imageBase: \t\t\t%016x" % imageBase)
		sectionAlignment = dword(data, ntHeader + 56)
		fileAlignment = dword(data, ntHeader + 60)
		sizeOfImage = dword(data, ntHeader + 80)
		sizeOfHeaders = dword(data, ntHeader + 84)
		NumberOfRvaAndSizes = dword(data, ntHeader + 132)
	elif optionalHeader_Magic == 0x10b: # 32bit
		imageBase = dword(data, ntHeader + 52)
		print("imageBase: \t\t\t%08x" % imageBase)
		sectionAlignment = dword(data, ntHeader + 56)
		fileAlignment = dword(data, ntHeader + 60)
		sizeOfImage = dword(data, ntHeader + 80)
		sizeOfHeaders = dword(data, ntHeader + 84)
		NumberOfRvaAndSizes = dword(data, ntHeader + 116)
	else:
		print(file + "Invalid magic number in optional image file header.")
		return False

	print ("Optional Header Magic (offset): %x" % optionalHeader_Magic)
	print ("AddressOfEntryPoint: \t\t%lx" % addressOfEntryPoint)
	if (addressOfEntryPoint < optionalHeaderSize):
		raise ValueError("AddressOfEntryPoint is not allowed to be smaller that optionalHeaderSize, except if it's null.")

	print ("sectionAlignment: \t\t%x" % sectionAlignment)
	print ("fileAlignment: \t\t\t%08x" % fileAlignment)
	print ("sizeOfImage: \t\t\t%08x" % sizeOfImage)
	print ("sizeOfHeaders: \t\t\t%08x" % sizeOfHeaders)
	print ("NumberOfRvaAndSizes: \t\t%08x" % NumberOfRvaAndSizes)

	# Read DATA_DIRECTORY (size 120)
	print "------------------DATA DIRECTORY----------------------------"
	print ("exportDirectoryRVA: \t\t%08x" % exportDirectoryRVA)
	print ("exportDirectorySize: \t\t%08x" % exportDirectorySize)
	print ("importDirectoryRVA: \t\t%08x" % importDirectoryRVA)
	print ("importDirectorySize: \t\t%08x" % importDirectorySize)
	print ("TLS RVA: \t\t\t%08x" % TLSrvaAddress)
	print ("TLS Size: \t\t\t%08x" % TLSDirectorySize)

	# Read SECTION HEADER
	print "------------------SECTION HEADER----------------------------"
	sectionHeader = dword(data, optionalHeaderSize + optionalHeader_Magic)

	for s in sections:
		print "%s -> \t%08x \t%08x \t%08x \t%08x" % s

	return True

def display_IAT(file_path, sections, data, optionalHeaderSize, optionalHeader_Magic, importDirectoryRVA, importDirectorySize):
	print "--------------------IMPORT TABLE----------------------------"

	if importDirectoryRVA==0 and importDirectorySize==0:
		raise ValueError ("Does not exist IMPORT DIRECTORY TABLE in the file.")
	else:
		offset_imports = convertRVAtoOffset(sections, importDirectoryRVA)
		if optionalHeader_Magic == 0x20b: # 64bit
			while dword(data, offset_imports) != 0:
				IMAGE_IMPORT_DESCRIPTOR = []
				OFTs = dword(data, offset_imports)

				name_rva = dword(data, offset_imports + 12)
				FTs = dword(data, offset_imports + 16) # FirstThunk
				IMAGE_IMPORT_DESCRIPTOR.append((name_rva, FTs))

				print "\nFTs: %x \t\tOFTs: %x" %(FTs, OFTs)

				# Read DLL names
				off_numedll = convertRVAtoOffset(sections, name_rva)
				nume_dll = getStringFromByteArray(data, off_numedll)
				print nume_dll

				# Read import name functions
				offsetFTS = convertRVAtoOffset(sections, FTs)
				offset_data_thunk = qword(data, offsetFTS)

				if (name_rva < FTs):
					raise ValueError("RVA is not inside the %s" % FTs)
				else:
					offsetOFTS = convertRVAtoOffset(sections, OFTs)
					offset_import_name_table = dword(data, offsetOFTS)

				crt_offsetOFTS = offsetOFTS
				crt_offsetFTS = offsetFTS
				ordinal_flag = 0x8000000000000000
				while qword(data, crt_offsetFTS) != 0:
					offset_data_thunk = qword(data, crt_offsetFTS)
					crt_offsetFTS += 8
					# Vad daca primul bit e setat (8)-> ordinal, altfel e rva
					if offset_data_thunk & ordinal_flag:
						print "\t\tOrdinal: %08x" % (offset_data_thunk &~ ordinal_flag)
						#continue
					else:
						# read rva
						offset_INT = qword(data, crt_offsetOFTS)
						name_offs = convertRVAtoOffset(sections, offset_INT)
						crt_offsetOFTS += 8
						hint, name = struct.unpack('<H128s', data[name_offs:name_offs+130])
						name = name.split('\0')[0]
						print('\t\tHint: %x, Name: %s'% (hint, name))
				offset_imports += 20 # IMAGE_IMPORT_DESCRIPTOR strcture is 20 bytes and contains info about a DLL which the PE file imports
		elif optionalHeader_Magic == 0x10b: # 32bit
			while dword(data, offset_imports) != 0:
				IMAGE_IMPORT_DESCRIPTOR = []
				OFTs = dword(data, offset_imports)

				name_rva = dword(data, offset_imports + 12)
				FTs = dword(data, offset_imports + 16) # FirstThunk
				IMAGE_IMPORT_DESCRIPTOR.append((name_rva, FTs))

				print "\nFTs: %x \t\tOFTs: %x" %(FTs, OFTs)

				# Read DLL names
				if (name_rva < FTs):
					raise ValueError("RVA is not inside the %s" % FTs)
				else:
					off_numedll = convertRVAtoOffset(sections, name_rva)
					nume_dll = getStringFromByteArray(data, off_numedll)
					print nume_dll

				# Read import name functions
				ordinal_flag = 0x80000000

				offsetFTS = convertRVAtoOffset(sections, FTs)
				offset_data_thunk = dword(data, offsetFTS)

				offsetOFTS = convertRVAtoOffset(sections, OFTs)
				offset_import_name_table = dword(data, offsetOFTS)

				crt_offsetOFTS = offsetOFTS
				crt_offsetFTS = offsetFTS

				while dword(data, crt_offsetFTS) != 0:
					offset_data_thunk = dword(data, crt_offsetFTS)
					crt_offsetFTS += 4
					# Vad daca primul bit e setat (8)-> ordinal, altfel e rva
					if offset_data_thunk & ordinal_flag:
						print "\t\tOrdinal: %08X" % (offset_data_thunk &~ ordinal_flag)
						continue

					# read rva
					offset_INT = dword(data, crt_offsetOFTS)
					name_offs = convertRVAtoOffset(sections, offset_INT)
					crt_offsetOFTS += 4
					hint, name = struct.unpack('<H128s', data[name_offs:name_offs+130])
					name = name.split('\0')[0]
					print('\t\tHint: %x, Name: %s'% (hint, name))

				offset_imports += 20

	return True

def display_EAT(file_path, sections, data, optionalHeaderSize, optionalHeader_Magic, ntHeader, exportDirectoryRVA, exportDirectorySize):
	print "----------------------EXPORT TABLE--------------------------"
	# Find .edata section where export table can be found
	exportSectionStart = 0
	exportSectionSize = 0
	IMAGE_EXPORT_DIRECTORY = 0
	for s in sections:
		if s[0] == ".edata":
			exportSectionStart = s[1]
			exportSectionSize = s[2]

	# Optional image file header
	if exportSectionStart == 0 and optionalHeaderSize > 0:
		IMAGE_EXPORT_DIRECTORY = 1
	if optionalHeader_Magic == 0x20b: # 64bit
		offset = ntHeader+24+104+IMAGE_EXPORT_DIRECTORY*8
		#offset = optionalHeader_Magic + 112
		exportSectionStart = dword(data, offset)
		exportSectionSize = dword(data, offset+4)
	elif optionalHeader_Magic == 0x10b: # 32bit
		offset = ntHeader+24+88+IMAGE_EXPORT_DIRECTORY*8
		#offset = optionalHeader_Magic + 96
		exportSectionStart = dword(data, offset)
		exportSectionSize = dword(data, offset+4)
	else:
		print(file_path + " - Invalid magic number in optional image file header.")
		return False

	print "exportDirectoryRVA: %x" %exportDirectoryRVA

	if exportDirectoryRVA==0 and exportDirectorySize==0:
		raise ValueError ("Does not exist EXPORT DIRECTORY TABLE in the file.")
	else:
		offs_exportStart = convertRVAtoOffset(sections, exportSectionStart)
		print "\nexportSectionStart: \t\t%x\nexportSectionSize: \t\t%x\n" % (offs_exportStart, exportSectionSize)

		Name = dword(data, offs_exportStart + 12)
		print "Name: \t\t\t\t%08x" % Name
		Base = dword(data, offs_exportStart + 16)
		print "Base (starting ordinal number): %08x" % Base
		NumberOfFunctions = dword(data, offs_exportStart + 20)
		print "NumberOfFunctions: \t\t%d" % NumberOfFunctions
		NumberOfNames = dword(data, offs_exportStart + 24)
		print "NumberOfNames: \t\t\t%08x" % NumberOfNames
		AddressOfFunctions = dword(data, offs_exportStart + 28)
		print "AddressOfFunctions: \t\t%08x" % AddressOfFunctions # RVA that points to an array of RVAs of the names of functions in the module (the EXPORT NAME TABLE)
		AddressOfNames = dword(data, offs_exportStart + 32)
		print "AddressOfNames: \t\t%08x" % AddressOfNames
		AddressOfNameOrdinals= dword(data, offs_exportStart + 36)
		print "AddressOfNameOrdinals: \t\t%08x" % AddressOfNameOrdinals # RVA that points to a 16bit array that contains the ordinal of the named functions (the EXPORT ORDINAL TABLE)

		# Read export table functions/ordinals
		if NumberOfNames == 0:
			#print("\nThe module may not have export functions!")
			print "\n"
			for i in range(NumberOfFunctions):
				print "\tOrdinal: %08x" % (Base+i)
		#elif NumberOfFunctions <= NumberOfNames:
		#	print("The function is exported by ordinal only. Functions does not have names.")
		else:
			print "\nEXPORT NAME FUNCTIONS: "
			offs_rva = convertRVAtoOffset(sections, AddressOfNames)
			for i in range(NumberOfNames):
				rva = dword(data, offs_rva+i*4) # rva that points to an array of RVAs of the names of functions in the module -> ENT
				off_names_rva = convertRVAtoOffset(sections, rva)
				fun_name = data[off_names_rva:off_names_rva+128].split(b'\0')[0].decode("utf8")
				print('\t%s' % fun_name)

	return True

def display_tls(file_path, sections, data, TLSrvaAddress, TLSDirectorySize):
	print "----------------------TLS DIRECTORY----------------------------"
	print "\nTLSrvaAddress: %x \t TLSDirectorySize: %x\n" % (TLSrvaAddress, TLSDirectorySize)

	if TLSrvaAddress==0 and TLSDirectorySize==0:
		raise ValueError ("Does not exist TLS DIRECTORY in the file.")
	else:
		offset = convertRVAtoOffset(sections, TLSrvaAddress)
		startAddressOfRawData = qword(data, offset)
		print "startAddressOfRawData: \t\t%016x" % startAddressOfRawData
		endAddressOfRawData = qword(data, offset+8)
		print "endAddressOfRawData: \t\t%016x" % endAddressOfRawData
		AddressOfIndex = qword(data, offset+16)
		print "AddressOfIndex: \t\t%016x" % AddressOfIndex
		AddressOfCallbacks = qword(data, offset+24)
		print "startAddressOfRawData: \t\t%016x" % AddressOfCallbacks
		SizeOfZeroFill = word(data, offset+32)
		print "SizeOfZeroFill: \t\t%08x" % SizeOfZeroFill
		Characteristics = dword(data, offset+36)
		print "Characteristics: \t\t%08x" % Characteristics

		'''
		if(AddressOfCallbacks > TLSDirectorySize):
			raise ValueError("AddressOfCallbacks is not inside the TLS Directory")
		else:
			offs_addrCallback = convertRVAtoOffset(sections, AddressOfCallbacks)
			callbacks = data[offs_addrCallback:offs_addrCallback+128].split(b'\0')[0]
			print('%s' % callbacks)
			for i in callbacks:
				print('\t%s' % i)
		'''

	return True

def main(file_path):
	myopts, args = getopt.getopt(sys.argv[1:], "d:h:i:e:t:")

	with open(file_path, 'rb') as input:
		data = bytearray(input.read())

	e_lfanew = dword(data, 60)
	ntHeader = e_lfanew
	nrSections = word(data, ntHeader+6)
	optionalHeaderSize = word(data, ntHeader + 20)
	optionalHeader_Magic = word(data, ntHeader + 24)

	if optionalHeader_Magic == 0x20b: # 64bit
		magic_offset = ntHeader+24+112
		exportDirectoryRVA = dword(data, magic_offset)
		exportDirectorySize = dword(data, magic_offset + 4)
		importDirectoryRVA = dword(data, magic_offset + 8)
		importDirectorySize = dword(data, magic_offset + 12)
		TLSrvaAddress = dword(data, magic_offset + 72)
		TLSDirectorySize = dword(data, magic_offset + 76)
		addressOfEntryPoint = dword(data, ntHeader + 40)
	elif optionalHeader_Magic == 0x10b: # 32bit
		magic_offset = ntHeader+24+96
		exportDirectoryRVA = dword(data, magic_offset)
		exportDirectorySize = dword(data, magic_offset + 4)
		importDirectoryRVA = dword(data, magic_offset + 8)
		importDirectorySize = dword(data, magic_offset + 12)
		TLSrvaAddress = dword(data, magic_offset + 72)
		TLSDirectorySize = dword(data, magic_offset + 76)
		addressOfEntryPoint = word(data, ntHeader + 40)
	else:
		print(file + "Invalid magic number in optional image file header.")
		return False

	sections = []
	for i in range(0, nrSections):
		offset = ntHeader+24+optionalHeaderSize+i*40
		sectionName = getStringFromByteArray(data, offset, 8)
		virtualSize = dword(data, offset + 8)
		virtualAddress = dword(data, offset + 12)
		sizeOfRawData = dword(data, offset + 16)
		PointerToRawData = dword(data, offset + 20) # raw address
		sections.append((sectionName, virtualAddress, virtualSize, PointerToRawData, sizeOfRawData))

	# o - option, a - argument passed to the object
	for o, a in myopts:
		if o == '-d':
			print "\nDISASSEMBLE INSTRUCTION FROM ENTRYPOINT:\n"
			display_instruction(file_path)
		elif o == '-h':
			display_headers(file_path, data, sections, e_lfanew, nrSections, addressOfEntryPoint, optionalHeader_Magic, optionalHeaderSize, exportDirectoryRVA, exportDirectorySize, importDirectoryRVA, importDirectorySize, TLSrvaAddress, TLSDirectorySize)
		elif o == '-i':
			display_IAT(file_path, sections, data, optionalHeaderSize, optionalHeader_Magic, importDirectoryRVA, importDirectorySize)
		elif o == '-e':
			print "eat"
			display_EAT(file_path, sections, data, optionalHeaderSize, optionalHeader_Magic, ntHeader, exportDirectoryRVA, exportDirectorySize)
		elif o == '-t':
			# print "[THREAD LOCAL STORAGE]:"
			 display_tls(file_path, sections, data, TLSrvaAddress, TLSDirectorySize)
		else:
			print "help: -d disassemble, -h show headers, -i show import table, -e show export table, -t show tls"

if __name__ == "__main__":
	print "\tDUMPING PE (PORTABLE EXECUTABLE) FILE:"
	main(sys.argv[2])
