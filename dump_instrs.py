#!/usr/bin/env python

import sys
import glob
import argparse

import envi
from decode import decode, vwopen, get_op_targets, TGT_TYPE


class LINE:
    def __init__(self, addr, data, op):
        self.addr = addr
        self.data = data
        self.op = op
        self._comment = ''
        self._str = None

    @property
    def width(self):
        return len(str(self))

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, comment):
        self._comment = comment
        self._str = None

    def __str__(self):
        if self._str is None:
            if self.op is None:
                self._str = '[0x%x] %-12s' % \
                        (self.addr, self.data.hex(' '))
            else:
                self._str = '[0x%x] %-12s  %s%s' % \
                        (self.addr, self.data.hex(' '), self.op, self.comment)
        return self._str

    @property
    def size(self):
        return self.op.size


class BLOCK:
    def __init__(self, idx, lines=None, targets=None):
        self.idx = idx

        if lines is None:
            self.lines = []
        else:
            self.lines = lines

        self.target_addrs = []

        if targets is None:
            self.targets = []
        else:
            self.targets = targets

    def __iter__(self):
        return iter(self.lines)

    def __getitem__(self, idx):
        return self.lines[idx]

    @property
    def width(self):
        return max(i.width for i in self.lines)

    def add(self, line):
        self.lines.append(line)

    def __len__(self):
        return sum(i.size for i in self.lines)

    @property
    def start(self):
        return self.lines[0].addr

    def __contains__(self, addr):
        return addr >= self.start and addr < (self.start + len(self))

    def split_at(self, addr):
        for idx, line in enumerate(self.lines):
            if line.addr == addr:
                break
        else:
            raise IndexError('address 0x%x not found in block %d' % (addr, self.idx))

        new_block_lines = self.lines[:idx]
        block.lines = self.lines[idx:]

        # Make a new block using the old index, and the updated old block index as
        # the only target (because it should be a simple fall through instruction)
        new_block = BLOCK(idx=self.idx, lines=new_block_lines, targets=[self.idx+1])

        # Now update the this block's index
        self.idx += 1

        # return the new block
        return new_block


def split_block(block_list, block_idx, addr):
    # Find the target block and split it into two parts
    new_block = block_list[block_idx].split_at(addr)

    # Before inserting the new block into the list, go through the list and
    # update any target that is > block_idx
    for block in block_list:
        for target in block.targets:
            if target > block_idx:
                block.target += 1

    # Now insert the new block
    block_list.insert(block_idx, new_block)

    # Return the id of the block that now contains the address
    return block_idx + 1


def decode_lines(in_file, va=0, arch=None, vle=False):
    _, emu = vwopen(arch)

    with open(in_file, 'rb') as f:
        firmware = f.read()
        offset = 0
        while offset < len(firmware):
            try:
                if firmware[offset:offset+4] == b'\xff\xff\xff\xff':
                    raise Exception()
                op = decode(emu, firmware, vle, offset=offset, va=va+offset, verbose=False)
                size = op.size
            except:
                op = None
                size = 2 if vle else 4

            data = firmware[offset:offset+size]
            yield LINE(va+offset, data, op)

            offset += size


def decode_blocks(in_file, va=0, arch=None, vle=False):
    # A Block is a tuple of (lines, next_blocks).  None in place of the next
    # block list indicates
    idx = 0
    blocks = [BLOCK(idx)]

    lines = list(decode_lines(in_file, va=va, arch=arch, vle=vle))
    while lines:
        line = lines.pop(0)
        tgts = get_op_targets(line.op)
        if tgts is None:
            blocks[idx].add(line)
            continue

        if TGT_TYPE.CALL in tgts:
            call_tgt = tgts[TGT_TYPE.CALL]
            if call_tgt is not None:
                # Attempt to find the decoded function binary, just in case it
                # is named
                try:
                    binfile = glob.glob('*_%x.bin' % call_tgt)[0]
                    filename = binfile[:-3] + 'txt'
                except IndexError:
                    # Make it what we guess it should be
                    filename = 'sub_%x.txt' % call_tgt
                line.comment = '  ; CALL ' + filename
            else:
                line.comment = '  ; CALL'

        # Add this instruction to the current block
        blocks[idx].add(line)

        # If this instruction branches or returns, this is the end of a
        # block
        if TGT_TYPE.BRANCH in tgts or TGT_TYPE.RET in tgts:
            # Just use the address at the moment since we don't know which block
            # this will be
            if TGT_TYPE.BRANCH in tgts:
                block[idx].target_addrs.append(tgts[TGT_TYPE.BRANCH])
            else:
                blocks[idx].target_addrs.append(tgts[TGT_TYPE.RET])

            # Add in the fall through target if present
            if TGT_TYPE.FALL in tgts:
                blocks[idx].target_addrs.append(tgts[TGT_TYPE.FALL])

            # Now start a new block
            idx += 1
            blocks.append(BLOCK(idx))

    # Identify the targets for each block, and split target blocks if necessary
    idx = 0
    while True:
        for tgt in blocks[idx].target_addrs:
            if tgt is None:
                blocks[idx].targets.append(None)
            else:
                try:
                    tgt_block = next(b.idx for b in blocks if tgt == b.start)
                    blocks[idx].targets.append(tgt_block)
                except StopIteration:
                    # target address is not the start of a block
                    try:
                        tgt_block = next(b.idx for b in blocks if tgt in b)

                        # Split the target block and get the index of the new
                        # block
                        tgt_block = split_block(blocks, tgt_block, tgt)
                        blocks[idx].targets.append(tgt_block)

                    except StopIteration:
                        # Target is unidentified
                        blocks[idx].targets.append('Unknown')
        idx += 1
        if idx >= len(blocks):
            break

    return blocks


def allocate_columns(block_list):
    # all blocks starts in the center column
    main_col = list(range(len(blocks)))
    left_cols = []
    right_cols = []
    for block in block_list:
        for target in block.targets:
            if target > block.idx + 1 and target not in right_cols:
                right_cols.append(target)
                main_col.remove(target)
            elif target <= block.idx and target not in left_cols:
                left_cols.append(target)

    return (left_cols, main_col, right_cols)


def decode_file(in_file, out_file=None, va=0, arch=None, vle=False, fancy=False):
    if arch is None:
        arch = 'ppc32-embedded'

    if out_file is None:
        outfd = sys.stdout
    else:
        outfd = open(out_file, 'w')

    blocks = list(decode_blocks(in_file, va=va, arch=arch, vle=vle))

    if fancy:
        left_cols, main_col, right_cols = allocate_columns(blocks)
        left_enabled = dict((i, False) for i in left_cols)
        right_enabled = dict((i, False) for i in right_cols)
        center_enabled = False

        # Find the width of the right column padding
        col_width = max(b.width for b in blocks)

        right_link = ' |' + (' ' * (col_width-2))
        right_pad = ' ' * col_width

        left_link = '  ‖  '
        left_pad = ' ' * len(left_link)

    else:
        left_pad = ''

    for block in blocks:
        if fancy:
            # Draw the backwards links
            left = ''.join(left_link if left_enabled[c] else left_pad for c in left_cols)

            # Now add any block indentation
            try:
                col_idx = right_cols.index(block.idx)
                left += right_link if center_enabled else right_pad
                left += ''.join(right_link if right_enabled[c] else right_pad for c in right_cols[:col_idx])
                right = ''.join(right_link if right_enabled[c] else right_pad for c in right_cols[col_idx+1:])
            except IndexError:
                right = ''.join(right_link if right_enabled[c] else right_pad for c in right_cols)
        else:
            left = ''
            line_pad = ''
            right = ''

        for line in block:
            if fancy:
                line_pad = ' ' * (col_width - line.width)
            print('%s%s%s%s' % (left, line, line_pad, right), file=outfd)

    if outfd != sys.stdout:
        outfd.close()


def main():
    ppc_arch_list = [n for n in envi.arch_names.values() if n.startswith('ppc')]

    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='file to dump instructions from')
    parser.add_argument('-v', '--vle', action='store_true', help='Decode instructions as VLE')
    parser.add_argument('-a', '--arch', default='ppc32-embedded', choices=ppc_arch_list)
    parser.add_argument('-b', '--baseaddr', default='0x00000000')
    args = parser.parse_args()

    va = int(args.baseaddr, 0)

    decode_file(args.filename, va=va, arch=args.arch, vle=args.vle)

if __name__ == '__main__':
    main()
