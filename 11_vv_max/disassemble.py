#!/usr/bin/env python3
import binascii

import cle

# Descriptions of each VM bytecode instruction, in opcode order
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

vv_max = cle.Loader('vv_max.exe')
vv_max.memory.seek(0x140015350)
code = vv_max.memory.read(0x5fb)

offset = 0
while code and code[0] != 0xff:
    instr_offset = offset
    opcode, code, offset = code[0], code[1:], (offset + 1)
    args = []
    for a in INSTRS[opcode]['args']:
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
    line = f'{instr_offset:>4}:\t{INSTRS[opcode]["mnemonic"]} {arglist}'
    print(line)
