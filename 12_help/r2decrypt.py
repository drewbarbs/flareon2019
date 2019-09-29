"""

Script to decrypt stack strings found in DLLs injected into userspace
processes by "man.sys" kernel modules in Flare-On 6 challenge 12.

Requires radare2 + r2pipe
"""

import argparse

import r2pipe

import pyrc4


def print_stack_strs(dll_path: str, rc4_func_addr: int, target_func_addr: int):
    r = r2pipe.open(dll_path)
    try:
        r.cmd('s {}'.format(target_func_addr))
        r.cmd('af')

        func_refs = r.cmdj('afxj')
        func_refs = [
            r for r in func_refs
            if r['type'] == 'call' and r['to'] == rc4_func_addr
        ]
        func_refs = list(sorted(func_refs, key=lambda r: r['from']))
        for ref in func_refs:
            r.cmd('s {}'.format(ref['from']))
            r.cmd('so -1')
            instr, = r.cmdj('pdj 1')
            assert (instr['opcode'].split(',')[0] == 'lea rcx')

            r.cmd('so -1')
            instr, = r.cmdj('pdj 1')
            assert (instr['opcode'].split(',')[0] == 'mov edx')
            keylen = instr['val']

            r.cmd('so -1')
            instr, = r.cmdj('pdj 1')
            assert (instr['opcode'].split(',')[0] == 'lea r8')

            r.cmd('so -1')
            instr, = r.cmdj('pdj 1')
            assert (instr['opcode'].split(',')[0] == 'mov r9d')
            dlen = instr['val']

            r.cmd('so -1')
            instr, = r.cmdj('pdj 1')
            assert (instr['opcode'].startswith('mov byte')
                    and instr['val'] == 0)

            encoding = 'utf8'
            r.cmd('so -1')
            instr, = r.cmdj('pdj 1')
            assert (instr['opcode'].startswith('mov byte'))
            if instr['val'] == 0:
                encoding = 'utf16'
            else:
                r.cmd('so 1')

            steps = 0
            while steps < (keylen + dlen):
                r.cmd('so -1')
                instr, = r.cmdj('pdj 1')
                assert (instr['opcode'].startswith('mov byte'))
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
            decrypted = pyrc4.rc4decrypt(keybytes, dbytes).decode(encoding)
            print('"{}" at {} (encoding: {})'.format(decrypted,
                                                     r.cmd('?v $$').strip(),
                                                     encoding))
    finally:
        r.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Decrypt stack strings in injected code')

    parser.add_argument('dll_path', help='Path to DLL to process')
    parser.add_argument('rc4_function_offset',
                        help='Offset in DLL of rc4 function',
                        type=lambda x: int(x, 0))
    parser.add_argument(
        'target_function_offset',
        help='Offset in DLL of function with stack strings to analyze',
        type=lambda x: int(x, 0))

    args = parser.parse_args()

    print_stack_strs(args.dll_path, args.rc4_function_offset,
                     args.target_function_offset)
