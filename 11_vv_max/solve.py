#!/usr/bin/env python3
import angr
import claripy

proj = angr.Project('./converted')
main_addr = proj.loader.find_symbol('main').rebased_addr
# Address of initializer for r0 (corresponds to vv_max.exe argv[1])
const0_addr = proj.loader.find_symbol('CONST0').rebased_addr
# Address of initializer for r1 (corresponds to vv_max.exe argv[2])
const1_addr = proj.loader.find_symbol('CONST1').rebased_addr

# Write "FLARE2019" into CONST0
proj.loader.memory.store(const0_addr, b'FLARE2019')

# Find address of ret instruction in main()
cfg = proj.analyses.CFGFast(force_complete_scan=False,
                            function_starts=[main_addr])
ret_block, = cfg.functions[main_addr].ret_sites
assert ret_block.bytestr[-1] == 0xc3
ret_addr = ret_block.addr + ret_block.size - 1

initial_state = proj.factory.entry_state()

simmgr = proj.factory.simulation_manager(initial_state)
simmgr.explore(find=main_addr).unstash(from_stash='found', to_stash='active')

active, = simmgr.active
arg2 = claripy.BVS('arg2', 0x20 * 8)
active.memory.store(const1_addr, arg2)

simmgr.explore(find=ret_addr)

found, = simmgr.found
found.solver.add(found.regs.eax == -1)

# Restrict solutions to be alphanumeric
for b in arg2.chop(8):
    found.solver.add(found.solver.Or(
        found.solver.And(b >= ord('A'), b <= ord('Z')),
        found.solver.And(b >= ord('a'), b <= ord('z')),
        found.solver.And(b >= ord('0'), b <= ord('9'))))

arg2_value = found.solver.eval_one(arg2, cast_to=bytes).decode('utf8')
print(f'arg2 needs to be "{arg2_value}"')
