import pefile

IMAGE_DIRECTORY_ENTRY_IMPORT = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
IMAGE_DIRECTORY_ENTRY_RESOURCE = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
IMAGE_DIRECTORY_ENTRY_EXCEPTION = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']
IMAGE_DIRECTORY_ENTRY_DEBUG = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
IMAGE_DIRECTORY_ENTRY_IAT = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']

with open('drivers/man.raw', 'rb') as f:
    MEMDMP = f.read()
    
with open('drivers/beep.sys', 'rb') as f:
    BEEP = f.read()

beep = pefile.PE('drivers/beep.sys')
pe_hdr_len = (beep.OPTIONAL_HEADER.get_file_offset() +
              beep.FILE_HEADER.SizeOfOptionalHeader)
text_section_h, *_, rsrc_section_h = beep.sections
assert text_section_h.Name.startswith(b'.text') and rsrc_section_h.Name.startswith(b'.rsrc')

hdrs = BEEP[text_section_h.get_file_offset():rsrc_section_h.get_file_offset()]


PATCHED = BEEP[:pe_hdr_len] + hdrs + MEMDMP[pe_hdr_len+len(hdrs):]

with open('tmp.sys', 'wb') as f:
    f.write(PATCHED)

pe = pefile.PE('tmp.sys')
pe.FILE_HEADER.NumberOfSections = 5

def fixup_section(s, va, sz):
    s.VirtualAddress = va
    s.PointerToRawData = va
    s.Misc_VirtualSize = sz
    s.SizeOfRawData = sz

fixup_section(pe.sections[0], 0x1000, 0x5000)
fixup_section(pe.sections[1], 0x6000, 0x6000)
fixup_section(pe.sections[2], 0xc000, 0x1000)
fixup_section(pe.sections[3], 0xd000, 0x1000)
fixup_section(pe.sections[4], 0xe000, 0x1000)

pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x5110
pe.OPTIONAL_HEADER.ImageBase = 0xfffff880033bc000
pe.OPTIONAL_HEADER.SizeOfCode = 0x5000
pe.OPTIONAL_HEADER.SizeOfImage = 0xf000

pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0xe000
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0xd000
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0x234
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0x60f0
pe.set_dword_at_offset(0x6108, 0x610c)
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0x6000
pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IAT].Size = 8*29

pe.write('man.sys')
