import struct

import lznt1
from scapy.all import rdpcap, TCP

from pyrc4 import rc4decrypt

pcap = rdpcap('help.pcapng')
sessions = pcap.sessions()

for session_no, (k, s) in enumerate(sessions.items()):
    payload = b''.join(bytes(p[TCP].payload) for p in s if TCP in p)
    for i in range(len(payload[:-4])):
        maybelen, = struct.unpack_from('<I', payload, i)
        if maybelen == len(payload) - i:
            try:
                with open('mass{}.bin'.format(session_no), 'wb') as f:
                    f.write(
                        lznt1.decompress(
                            rc4decrypt(b'FLARE ON 2019\x00', payload[i + 4:])))
            except Exception as e:
                print('Error processing {}: {}'.format(session_no, e))
