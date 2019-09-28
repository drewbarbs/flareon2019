import sys
import struct

import lznt1

from scapy.all import *

def KSA(key):
    keylength = len(key)

    S = list(range(256))

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap

    return S


def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap

        K = S[(S[i] + S[j]) % 256]
        yield K


def RC4(key):
    S = KSA(bytearray(key))
    return PRGA(S)


def do_decrypt(key, buf):
    keystream = RC4(key)
    return bytes(bytearray(ord(b) ^ k for b, k in zip(buf, keystream)))


pcap = rdpcap('help.pcapng')
for i, p in enumerate(pcap):
    if TCP in p and len(p[TCP].payload) >= 4:
        payload = bytes(p[TCP].payload)
        maybelen, = struct.unpack('<I', payload[:4])
        if maybelen == len(payload):
            try:
                with open('mass{}.bin'.format(i), 'wb') as f:
                    f.write(lznt1.decompress(do_decrypt(b'FLARE ON 2019\x00', payload[4:])))
            except Exception as e:
                print('Error processing {}: {}'.format(i, e))
