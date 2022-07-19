#!/usr/bin/env python

import argparse

import decode

def main():
    ppc_arch_list = [n for n in decode.envi.arch_names.values() if n.startswith('ppc')]

    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='file to dump instructions from')
    parser.add_argument('-v', '--vle', action='store_true', help='Decode instructions as VLE')
    parser.add_argument('-a', '--arch', default='ppc32-embedded', choices=ppc_arch_list)
    parser.add_argument('-b', '--baseaddr', default='0x00000000')
    args = parser.parse_args()

    va = int(args.baseaddr, 0)

    vw, emu = decode.vwopen(args.arch)
    with open(args.filename, 'rb') as f:
        firmware = f.read()
        offset = 0
        while offset < len(firmware):
            try:
                if firmware[offset:offset+4] == b'\xff\xff\xff\xff':
                    raise Exception()
                op = decode.decode(emu, firmware[offset:offset+4], args.vle,
                        prefix='[0x%08x] ' % va+offset, va=va+offset)
                offset += op.size
            except:
                size = 2 if args.vle else 4
                print('[0x%08x]' % va+offset, ' '.join('%02x' % v for v in firmware[offset:offset+size]))
                offset += size

if __name__ == '__main__':
    main()
