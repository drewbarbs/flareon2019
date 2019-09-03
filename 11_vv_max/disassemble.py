import binascii
import r2pipe

r = r2pipe.open('vv_max.exe')
r.cmd('s 0x140015350')
code = r.cmdj('pxj 1531')
r.quit()

INSTRS = [
    {'mnemonic': 'clearregs', 'args': []},
    {'mnemonic': 'vpmaddubsw', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpmaddwd', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpxor', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpor', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpand', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'bitwise_not', 'args': ['r', 'r']},
    {'mnemonic': 'vpaddb', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpsubb', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpaddw', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpsubw', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpaddd', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpsubd', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpaddq', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpsubq', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpmulq', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'movreg', 'args': ['r', 'r']},
    {'mnemonic': 'movimm', 'args': ['r', 'imm256']},
    {'mnemonic': 'vpsrld', 'args': ['r', 'r', 'imm8']},
    {'mnemonic': 'vpslld', 'args': ['r', 'r', 'imm8']},
    {'mnemonic': 'vpshufb', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpermd', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'vpcmpeqb', 'args': ['r', 'r', 'r']},
    {'mnemonic': 'nop', 'args': []}
]

offset = 0
while code and code[0] != 0xff:
    code_offset = offset
    instr, code, offset = code[0], code[1:], (offset + 1)
    args = []
    for a in INSTRS[instr]['args']:
        if a == 'r':
            rnum, code, offset = code[0], code[1:], (offset + 1)
            args.append(f'r{rnum}')
        elif a == 'imm256':
            imm, code, offset = code[:32], code[32:], (offset + 32)
            args.append(binascii.hexlify(bytes(bytearray(imm))).decode('utf8'))
        elif a == 'imm8':
            imm, code, offset = code[0], code[1:], (offset + 1)
            args.append(f'{hex(imm)}')
        else:
            raise Exception(f'Unrecognized argument type {a}')
    arglist = ', '.join(args)
    line = f'{code_offset}:\t{INSTRS[instr]["mnemonic"]} {arglist}'
    print(line)
