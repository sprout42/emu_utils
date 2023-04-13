#!/usr/bin/env python

import re
import glob
import os.path

from dump_instrs import decode_file


def main():
    bin_file_pat = re.compile(r'(.*([0-9a-fA-F]+)).bin')
    for filename in glob.glob('*.bin'):
        m = bin_file_pat.match(filename)
        assert m
        txt_file_name = '%s.txt' % m.group(1)
        if not os.path.exists(txt_file_name):
            va = int(m.group(2), 16)
            #print('decode_file(%s, %s, va=0x%x, fancy=True)' % (filename, txt_file_name, va))
            print('decoding %s' % filename)
            decode_file(filename, txt_file_name, va=va, fancy=True, print_block_headers=True)


if __name__ == '__main__':
    main()
