import itertools
from PIL import Image

def getbit(byts, idx):
    byte = byts[idx // 8]
    bitidx = idx % 8
    if bitidx == 0:
        return (byte & 0x80) >> 7
    elif bitidx == 1:
        return (byte & 0x40) >> 6
    elif bitidx == 2:
        return (byte & 0x20) >> 5
    elif bitidx == 3:
        return (byte & 0x10) >> 4
    elif bitidx == 4:
        return (byte & 0x8) >> 3
    elif bitidx == 5:
        return (byte & 0x4) >> 2
    elif bitidx == 6:
        return (byte & 0x2) >> 1
    else:  # bitidx == 7:
        return (byte & 0x1)

def convert_patterns(ptable, img):
    patterns = zip(*[iter(ptable)]*16)
    for patnum, pattern in enumerate(patterns):
        startrow = (patnum//16) * 8
        startcol = (patnum % 16) * 8

        plane0 = pattern[:8]
        plane1 = pattern[8:]
        for r, c in itertools.product(range(8), range(8)):
            bitnum = r * 8 + c
            pix = getbit(plane0, bitnum) | getbit(plane1, bitnum)
            img.putpixel((startcol + c, startrow + r), pix)


with open('snake.nes', 'rb') as f:
    ROM = f.read()

img = Image.new('1', (16 * 8, 16 * 8))
pattern_table0 = ROM[0x4010:0x5010]
convert_patterns(pattern_table0, img)
img.save('pt0.png')

img = Image.new('1', (16 * 8, 16 * 8))
pattern_table1 = ROM[0x5010:0x6010]
convert_patterns(pattern_table1, img)
img.save('pt1.png')
