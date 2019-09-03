#!/usr/bin/env python3
import angr
import claripy

proj = angr.Project('./main')

arg1 = claripy.BVS('arg1', 0x20 * 8)

initial_state = proj.factory.entry_state(args=['test', arg1])

for b in arg1.chop(8):
    initial_state.add_constraints(b != 0)

simmgr = proj.factory.simulation_manager(initial_state)
simmgr.explore(find=0x40115a).unstash(from_stash='found', to_stash='active')
active, = simmgr.active

arg1 = claripy.BVS('arg1', 8*0x20)

active.memory.store(active.regs.rax, arg1)
simmgr.explore(find=0x4011c4)

found, = simmgr.found
