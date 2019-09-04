#!/usr/bin/env python3
import subprocess

import angr
import claripy

proj = angr.Project('./converted')

arg2 = claripy.BVS('arg2', 0x20 * 8)

initial_state = proj.factory.entry_state()

simmgr = proj.factory.simulation_manager(initial_state)
simmgr.explore(find=0x40147a).unstash(from_stash='found', to_stash='active')

active, = simmgr.active
active.memory.store(active.regs.rax, arg2)

# for b in arg2.chop(8):
#     active.add_constraints(b != 0)
#     active.add_constraints(b >= ord(' '))
#     active.add_constraints(b <= ord('~'))

simmgr.explore(find=0x4040e7)

found, = simmgr.found

for b in arg2.chop(8):
    found.solver.add(found.solver.Or(
        found.solver.And(b >= ord('A'), b <= ord('Z')),
        found.solver.And(b >= ord('a'), b <= ord('z')),
        found.solver.And(b >= ord('0'), b <= ord('9')),
        b == ord('+'),
        b == ord('/')))

solutions = found.solver.eval_upto(arg2, 100, cast_to=bytes)
