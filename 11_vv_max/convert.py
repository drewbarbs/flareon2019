#!/usr/bin/env python3
import textwrap

import cle

INSTRS = [
    {},  # clearregs, dont bother implementing
    {'mnemonic': 'vpmaddubsw', 'args': ['r', 'r'], 'intrinsic': '_mm256_maddubs_epi16'},
    {'mnemonic': 'vpmaddwd', 'args': ['r', 'r'], 'intrinsic': 'do_vpmaddwd'},
    {'mnemonic': 'vpxor', 'args': ['r', 'r'], 'intrinsic': '_mm256_xor_si256'},
    {'mnemonic': 'vpor', 'args': ['r', 'r'], 'intrinsic': '_mm256_or_si256'},
    {'mnemonic': 'vpand', 'args': ['r', 'r'], 'intrinsic': '_mm256_and_si256'},
    {},  # bitwise_not, unused
    {'mnemonic': 'vpaddb', 'args': ['r', 'r'], 'intrinsic': '_mm256_add_epi8'},
    {},  # vpsubb, unused
    {},  # vpaddw, unused
    {},  # vpsubw, unused
    {'mnemonic': 'vpaddd', 'args': ['r', 'r'], 'intrinsic': '_mm256_add_epi32'},
    {},  # vpsubd, unused
    {},  # vpaddq, unused
    {},  # vpsubq, unused
    {},  # vpmulq, unused
    {},  # movreg, unused
    {'mnemonic': 'movimm', 'args': ['imm256']},
    {'mnemonic': 'vpsrld', 'args': ['r', 'imm8'], 'intrinsic': '_mm256_srli_epi32'},
    {'mnemonic': 'vpslld', 'args': ['r', 'imm8'], 'intrinsic': '_mm256_slli_epi32'},
    {'mnemonic': 'vpshufb', 'args': ['r', 'r'], 'intrinsic': '_mm256_shuffle_epi8'},
    {'mnemonic': 'vpermd', 'args': ['r', 'r'], 'intrinsic': '_mm256_permutevar8x32_epi32'},
    {'mnemonic': 'vpcmpeqb', 'args': ['r', 'r'], 'intrinsic': '_mm256_cmpeq_epi8'},
    {}   # nop, unused
]

TEMPLATE = '''
#include <immintrin.h>

{constants}

{vpmaddwd_implementation}

int main(int argc, char **argv) {{
    // Code to initialize variables r0-r31 to zero
{zero_init_regs}
    // Converted bytecode
{body}

    // Replicate the checks from the function at 140001610 of vv_max.exe
    __m256i cmpresult = _mm256_cmpeq_epi8(r2, r20);
    int32_t result = _mm256_movemask_epi8(cmpresult);

    // We want result == -1
    return result;
}}
'''

VPMADDWD_IMPLEMENTATION = '''
__m256i do_vpmaddwd(__m256i a, __m256i b) {
    int32_t intermediate[16] = {0};
    int32_t result[8] = {0};
    for (int i = 0; i < 16; ++i) {
        intermediate[i] = ((int16_t*)&a)[i] * ((int16_t*)&b)[i];
    }

    for (int i = 0; i < 8; ++i) {
        result[i] = intermediate[2*i] + intermediate[2*i + 1];
    }

    return _mm256_loadu_si256((__m256i const *)result);
}
'''

vv_max = cle.Loader('vv_max.exe')
vv_max.memory.seek(0x140015350)
code = vv_max.memory.read(0x5fb)

code = code[1:]  # skip the first instruction "clearregs"
constants = []
statements = []

while code and code[0] != 0xff:
    opcode, dstreg, code = code[0], code[1], code[2:]

    if INSTRS[opcode]['mnemonic'] == 'movimm':
        immediate, code = code[:32], code[32:]
        immarr = '{' + ', '.join(hex(b) for b in immediate) + '}'
        constsym = f'CONST{len(constants)}'
        constdecl = f'const char {constsym}[32] = {immarr};'
        constants.append(constdecl)
        statements.append(f'r{dstreg} = _mm256_loadu_si256((__m256i const *){constsym});')
        continue

    instrinfo = INSTRS[opcode]
    args = []
    for argtype in instrinfo['args']:
        if argtype == 'r':
            rnum, code = code[0], code[1:]
            args.append(f'r{rnum}')
        elif argtype == 'imm8':
            imm, code = code[0], code[1:]
            args.append(f'{hex(imm)}')
        else:
            raise Exception(f'Unrecognized argument type {argtype}')
    intrinsic = instrinfo['intrinsic']
    arglist = ', '.join(args)
    statements.append(f'r{dstreg} = {intrinsic}({arglist});')

src = TEMPLATE.format(
    constants='\n'.join(constants),
    vpmaddwd_implementation=VPMADDWD_IMPLEMENTATION,
    zero_init_regs=textwrap.indent('\n'.join(f'__m256i r{i} = _mm256_setzero_si256();'
                                             for i in range(32)),
                                   ' '*4),
    body=textwrap.indent('\n'.join(statements), ' '*4))

print(src)
