import argparse

import envi
import vivisect.cli

def emulate(filename, funcname):
    vw = vivisect.cli.VivCli()
    vw.loadFromFile(filename)
    emu = vw.getEmulator(funconly=False)

    i = 0
    # The filename used to tag locations can be mangled sometimes, we've only 
    # loaded one file so we can just assume the first entry is correct.
    vivfileprefix = vw.getFiles()[0]

    entry = vw.parseExpression(vivfileprefix + '.' + funcname)
    emu.setProgramCounter(entry)
    emu.setRegisterByName('lr', 0xCAFECAFE)

    va = emu.getProgramCounter()
    while True:
        op = emu.parseOpcode(va)
        print('%d\t0x%08x\t0x%08x, op: %s' % (i, op.va, emu.readMemValue(op.va, 4), op))
        emu.stepi()
        va = emu.getProgramCounter()
        if va == 0xCAFECAFE:
            print('DONE')
            break
        i += 1


def print_entry_points(filename):
    vw = vivisect.cli.VivCli()
    vw.loadFromFile(filename)

    for va in vw.getEntryPoints():
        print(hex(va), vw.getName(va))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('funcname', nargs='?')
    args = parser.parse_args()

    if not args.funcname:
        print_entry_points(args.filename)
    else:
        emulate(args.filename, args.funcname)
