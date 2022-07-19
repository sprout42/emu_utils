#!/usr/bin/env python3

import argparse

import envi
import vivisect


def start(arch=None, endian=envi.const.ENDIAN_MSB):
    global vw, emu

    vw = vivisect.VivWorkspace()
    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform', 'unknown')
    vw.setMeta('Format', 'blob')
    vw.setMeta('bigend', envi.const.ENDIAN_MSB)
    vw.setMeta('DefaultCall', vivisect.const.archcalls.get(arch, 'unknown'))
    print('workspace arch set to %s' % arch)

    emu = vw.getEmulator()

    from IPython import embed
    embed(colors='neutral')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    ppc_arch_list = [n for n in envi.arch_names.values() if n.startswith('ppc')]
    parser.add_argument('-a', '--arch', default='ppc32-embedded', choices=ppc_arch_list)
    parser.add_argument('-e', '--endian', type=int, default=1, choices=[0, 1])

    args = parser.parse_args()

    start(args.arch, args.endian)
