#!/usr/bin/env python3

import argparse

import envi
import vivisect
import envi.const


def start(arch=None, endian=envi.const.ENDIAN_LSB, firmware=None, baseaddr=0, entrypoint=None):
    global vw, emu

    vw = vivisect.VivWorkspace()
    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform', 'unknown')
    vw.setMeta('Format', 'blob')
    vw.setMeta('bigend', envi.const.ENDIAN_MSB)
    print('workspace arch set to %s' % arch)

    # if a firmware file is specified load it
    if firmware:
        with open(firmware, 'rb') as f:
            vw.addMemoryMap(baseaddr, envi.const.MM_RWX, firmware, f.read())

    emu = vw.getEmulator()

    if entrypoint:
        emu.setProgramCounter(entrypoint)

    from IPython import embed
    embed(colors='neutral')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    arch_list = list(envi.arch_names.values())
    parser.add_argument('-a', '--arch', default='ppc32-embedded', choices=arch_list)
    parser.add_argument('-e', '--endian', type=int, default=0, choices=[0, 1])
    parser.add_argument('-f', '--firmware')
    parser.add_argument('-b', '--baseaddr', default='0')
    parser.add_argument('-E', '--entrypoint')

    args = parser.parse_args()

    baseaddr = int(args.baseaddr, 0)

    if args.entrypoint:
        entrypoint = int(args.entrypoint, 0)
    else:
        entrypoint = None

    start(args.arch, args.endian, firmware=args.firmware, baseaddr=baseaddr, entrypoint=entrypoint)
