import collections
import struct

with open('snake.nes', 'rb') as f:
    ROM = f.read()

iNES = collections.namedtuple('iNES',
                              ['magic',
                               'szPRGROM',
                               'szCHRROM',
                               'flags6',
                               'flags7',
                               'szPRGRAM',
                               'flags9',
                               'flags10',
                               'pad'])

header = iNES(*struct.unpack('4sBBBBBBB5s', ROM[:16]))
is_iNES2 = (header.flags7 & 0x0C) == 0x08
mapper_number = (header.flags7 & 0xf0) | ((header.flags6 & 0xf0) >> 4)

print(f'''
Size of PRGROM: {header.szPRGROM * 16}KB
Size of CHRROM: {header.szCHRROM * 8}KB
iNES 2? : {is_iNES2}
mapper: {mapper_number}
'''.strip())
