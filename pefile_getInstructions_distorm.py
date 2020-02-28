import pefile
import sys
import pydasm
import distorm3

def find_ep_section(pe, ep_rva): #check whether the section contains the address
    for section in pe.sections:
        if section.contains_rva(ep_rva):
            return section
    return None

def main(file_path):
	pe = pefile.PE(file_path)
	
	# Store the file data in a variable
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

	code_section = find_ep_section(pe, offset)
	if not code_section:
		return
	
	#Start disassembly at the EP: pentru a extrage instructiuni se porneste de la PointerToRawData (File Pointer catre datele RAW)
	print("Entry point is at offset: {:#x}".format(code_section.PointerToRawData))

	print "\n\tInstructions: "
	for i in range(10):
		# Get the first instruction
		i = pydasm.get_instruction(data[offset:], pydasm.MODE_32) #get_instruction(data to be disassembled, disassemble in 32-bit mode)
		
		# Print the parsed isntructions
		instructiuni = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset)
		print instructiuni
	
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

		
if __name__ == "__main__":
	main("safari.exe")