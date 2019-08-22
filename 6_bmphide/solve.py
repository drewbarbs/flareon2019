#!/usr/bin/env python3
import argparse
from itertools import count
from PIL import Image

# rol and ror from https://gist.github.com/trietptm/5cd60ed6add5adad6a34098ce255949a

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits: \
    (val << r_bits%8) & (2**8-1) | \
    ((val & (2**8-1)) >> (8-(r_bits%8)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits: \
    ((val & (2**8-1)) >> r_bits%8) | \
    (val << (8-(r_bits%8)) & (2**8-1))


def getbyte(pixel):
    r, g, b = pixel
    low3 = r & 7
    mid3 = g & 7
    high2 = b & 3

    return (high2 << 6) | (mid3 << 3) | low3


def f(idx):
    b = ((idx + 1) * 309030853) & 0xff
    k = ((idx + 2) * 209897853) & 0xff
    return b ^ k


def invert(byts):
    g = map(f, count(0))
    inverted = []
    for b in byts:
        g1, g2 = next(g), next(g)

        n = rol(b, 3)
        n = n ^ g2
        n = ror(n, 7)
        n = n ^ g1

        inverted.append(n)
    return inverted


def main():
    parser = argparse.ArgumentParser(description='Extract file from BMP')
    parser.add_argument('inp', help='Path to input file')
    parser.add_argument('outp', help='Path to output file')

    args = parser.parse_args()

    im = Image.open(args.inp)
    transformed = [getbyte(im.getpixel((col, row)))
                   for col in range(im.width)
                   for row in range(im.height)]
    inverted = invert(transformed)
    with open(args.outp, 'wb') as outfile:
        outfile.write(bytes(bytearray(inverted)))


if __name__ == '__main__':
    main()

im = Image.open('image.bmp')
