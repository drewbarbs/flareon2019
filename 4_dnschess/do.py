#!/usr/bin/env python3

import shlex
import subprocess

import r2pipe

p = subprocess.run(shlex.split('tshark -r capture.pcap -Y "dns.flags.response == 1" -T fields -e "dns.a"'),
                   stdout=subprocess.PIPE)

ips = [l.split(',')[0] for l in p.stdout.decode('utf8').split('\n') if l]
print(ips)
key = {(int(ip.split('.')[2]) & 0xf): int(ip.split('.')[1]) for ip in ips if int(ip.split('.')[3]) % 2 == 0}

r = r2pipe.open('ChessAI.so')
r.cmd('s 0x2020')

encrypted = r.cmdj('pxj 30')

decrypted = [b ^ key[i//2] for i, b in enumerate(encrypted)]

print(bytes(bytearray(decrypted)).decode('utf8') + '@flare-on.com')
