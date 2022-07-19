#!/usr/bin/env python3

import enum
import struct
import argparse

import decode

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bytes', nargs='+', help='Bytes to decode')
    parser.add_argument('-q', '--quiet', action='store_true', help='supress all extra decode information')
    parser.add_argument('-b', '--baseaddr', default='0x00000000')
    args, extra = parser.parse_known_args()

    ecu = cm2350.CM2350(extra)
    print('\n----------------------\nCM2350 ECU initialized\n----------------------\n')
    for arg in args.bytes:
        op = decode.decode(ecu.emu, arg, args.vle, va=va)
        if not args.quiet:
            cat = find_category(emu, arg, op)
            dump(op, cat)
            print()


if __name__ == '__main__':
    main()
