import sys
import r2pipe
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

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
    S = KSA(key)
    return PRGA(S)


def do_decrypt(key: bytes, buf: bytes):
    keystream = RC4(key)
    return bytes(bytearray(b ^ k for b, k in zip(buf, keystream)))


r = r2pipe.open('2410000.dll')
r.cmd('s {}'.format(sys.argv[1]))
r.cmd('af')

func_refs = r.cmdj('afxj')
func_refs = [r for r in func_refs if r['type'] == 'call' and r['to'] == 0x1150]
func_refs = list(sorted(func_refs, key=lambda r: r['from']))
for ref in func_refs:
   r.cmd('s {}'.format(ref['from']))
   r.cmd('so -1')
   instr, = r.cmdj('pdj 1')
   assert(instr['opcode'].split(',')[0] == 'lea rcx')

   r.cmd('so -1')
   instr, = r.cmdj('pdj 1')
   assert(instr['opcode'].split(',')[0] == 'mov edx')
   keylen = instr['val']

   r.cmd('so -1')
   instr, = r.cmdj('pdj 1')
   assert(instr['opcode'].split(',')[0] == 'lea r8')

   r.cmd('so -1')
   instr, = r.cmdj('pdj 1')
   assert(instr['opcode'].split(',')[0] == 'mov r9d')
   dlen = instr['val']

   r.cmd('so -1')
   instr, = r.cmdj('pdj 1')
   assert(instr['opcode'].startswith('mov byte') and instr['val'] == 0)

   u16 = False
   r.cmd('so -1')
   instr, = r.cmdj('pdj 1')
   assert(instr['opcode'].startswith('mov byte'))
   if instr['val'] == 0:
       u16 = True
   else:
       r.cmd('so 1')

   steps = 0
   while steps < (keylen + dlen):
       r.cmd('so -1')
       instr, = r.cmdj('pdj 1')
       assert(instr['opcode'].startswith('mov byte'))
       steps += 1

   keybytes = []
   for i in range(keylen):
       instr, = r.cmdj('pdj 1')
       keybytes.append(instr['val'])
       r.cmd('so 1')

   dbytes = []
   for i in range(dlen):
       instr, = r.cmdj('pdj 1')
       dbytes.append(instr['val'])
       r.cmd('so 1')

   r.cmd('so 4')
   decrypted = do_decrypt(keybytes, dbytes).decode('utf16' if u16 else 'utf8')
   print('"{}" at {} (unicode: {})'.format(decrypted, r.cmd('?v $$').strip(), u16))
