import binascii
import textwrap

import r2pipe

from collections import Counter

r = r2pipe.open('vv_max.exe')
r.cmd('s 0x140015350')
code = r.cmdj('pxj 1531')
r.quit()

INSTRS = [
    {},  # clearregs, dont bother implementing
    {'mnemonic': 'vpmaddubsw', 'args': ['r', 'r'], 'intrinsic': '_mm256_maddubs_epi16'},
    {'mnemonic': 'vpmaddwd', 'args': ['r', 'r'], 'intrinsic': '_mm256_madd_epi16'},
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

{initializers}

int main(int argc, char **argv) {{

{zero_init}

{body}

    __m256i cmpresult = _mm256_cmpeq_epi8(r2, r20);
    int32_t result = _mm256_movemask_epi8(cmpresult);

    if (result == -1) {{
        return 0;
    }} else {{
        return 1;
    }}

}}
'''

init_counter = Counter()
code = code[1:]  # skip the first instruction "clearregs"
initializers = []
statements = []

while code and code[0] != 0xff:
    instr, dstreg, code = code[0], code[1], code[2:]

    if INSTRS[instr]['mnemonic'] == 'movimm':
        immediate, code = code[:32], code[32:]
        if dstreg == 0:
            immediate = b'FLARE2019'
            immediate += b'\x00'*(32 - len(immediate))
        elif dstreg == 1:
            import string
            immediate = string.ascii_letters[:32].encode('utf8')

        immarr = '{' + ', '.join(hex(b) for b in immediate) + '}'
        initcount = init_counter[dstreg]
        init_counter[dstreg] += 1
        initsym = f'R{dstreg}_INIT{initcount}'
        initdecl = f'const char {initsym}[32] = {immarr};'
        initializers.append(initdecl)
        statements.append(f'r{dstreg} = _mm256_loadu_si256((__m256i const *){initsym});')
        continue

    instrinfo = INSTRS[instr]
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
    initializers='\n'.join(initializers),
    zero_init=textwrap.indent('\n'.join(f'__m256i r{i} = _mm256_setzero_si256();'
                                        for i in range(32)),
                              ' '*4),
    body=textwrap.indent('\n'.join(statements), ' '*4))

print(src)
