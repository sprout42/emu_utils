#!/usr/bin/env python3

import enum
import struct
import argparse

import envi
import vivisect

import envi.archs.ppc.const as _eapc
OPCODE = enum.IntEnum('OPCODE', dict((a, getattr(_eapc, a)) for a in dir(_eapc) if a.startswith('INS_')))
CAT = enum.IntEnum('CAT', dict((a, getattr(_eapc, a)) for a in dir(_eapc) if a.startswith('CAT_')))

flag_attrs = [('ARCH_PPC', envi.ARCH_PPC_E32)]
flag_attrs += [(a, getattr(_eapc, a)) for a in dir(_eapc) if a.startswith('IF_')]
flag_attrs += [(a, getattr(envi, a)) for a in dir(envi) if a.startswith('IF_')]
IFLAGS = enum.IntFlag('IFLAGS', dict(flag_attrs))


def print_flag_names(value):
    return '|'.join(v.name for v in list(value.__class__) if int(value)&int(v))


def dump(op, cat):
    #print(op)
    opcode = OPCODE(op.opcode)
    print('%s (%d)' % (opcode.name, opcode.value))
    try:
        category = CAT(cat)
        print('%s (0x%x)' % (category.name, category.value))
    except ValueError:
        # CAT_VLE isn't an official category we have so print it differently
        print('%s (N/A)' % cat)

    # Print the ILFAGS
    print('%s (0x%x)' % (print_flag_names(IFLAGS(op.iflags)), op.iflags))

    print(vars(op))
    for i, o in enumerate(op.opers):
        print('%d: (type %s)' % (i, type(o)))
        print(vars(o))


def arg2bytes(arg, is_vle=False):
    if isinstance(arg, bytes):
        return arg

    try:
        data = bytes.fromhex(arg)
    except TypeError:
        if is_vle:
            # If the VLE flag is set the size to decode is either 32 or 16
            # bits, use the string length of the argument as a hint to the
            # number of bytes
            data = data.to_bytes((len(data) // 2) - 2, 'big')
        else:
            # If not vle force instructions to be 4 bytes long
            data = arg.to_bytes(4, 'big')

    return data


def decode(emu, arg, is_vle=False, prefix='', va=0):
    data = arg2bytes(arg, is_vle)

    if is_vle:
        op = emu._arch_vle_dis.disasm(data, offset=0, va=va)
    else:
        op = emu.archParseOpcode(data, offset=0, va=va)

    print('%s%s:  %s' % (prefix, data.hex(), op))
    return op


def find_category(emu, arg, op):
    # If the instruction is e_ or se_ op then it's VLE, otherwise find it's
    # category
    if op.mnem.startswith('e_') or op.mnem.startswith('se_'):
        return 'CAT_VLE'

    data = arg2bytes(arg)

    # If a match hasn't been found yet fall back on the normal PPC disassembly
    # stragety
    # Basically a partial copy of the PpcDisasm.disasm() function
    dis = emu._arch_dis

    ival, = struct.unpack(dis.fmt, data)
    key = ival >> 26

    group = dis._instr_dict.get(key)
    for mask in group:
        masked_ival = ival & mask
        try:
            _, _, _, cat, _, _ = group[mask][masked_ival]
            return cat
        except KeyError:
            pass


def vwopen(arch=None):
    vw = vivisect.VivWorkspace()

    # Copied from vivisect/parsers/blob.py
    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform', 'unknown')
    vw.setMeta('Format', 'blob')
    vw.setMeta('bigend', envi.const.ENDIAN_MSB)
    vw.setMeta('DefaultCall', vivisect.const.archcalls.get(arch, 'unknown'))

    emu = vw.getEmulator()

    return vw, emu


def main():
    ppc_arch_list = [n for n in envi.arch_names.values() if n.startswith('ppc')]

    parser = argparse.ArgumentParser()
    parser.add_argument('bytes', nargs='+', help='Bytes to decode')
    parser.add_argument('-v', '--vle', action='store_true', help='Decode instructions as VLE')
    parser.add_argument('-a', '--arch', default='ppc32-embedded', choices=ppc_arch_list)
    parser.add_argument('-q', '--quiet', action='store_true', help='supress all extra decode information')
    parser.add_argument('-b', '--baseaddr', type=int, default=0)
    args = parser.parse_args()

    va = int(args.baseaddr, 0)

    vw, emu = vwopen(args.arch)
    print('\n----------------------\n%s workspace opened\n----------------------\n' % args.arch)
    for arg in args.bytes:
        op = decode(emu, arg, args.vle, va=va)
        if not args.quiet:
            cat = find_category(emu, arg, op)
            dump(op, cat)
            print()


if __name__ == '__main__':
    main()