import marshal
import uncompyle6

with open('boot2.bin', 'rb') as f:
    co = marshal.load(f)

with open('out.py', 'w') as out:
    uncompyle6.main.decompile(3.7, co, out)
