#!/usr/bin/env python

import sys
import glob
import argparse

import envi
from decode import decode, vwopen, get_op_targets, TGT_TYPE


class LINE:
    def __init__(self, addr, data, op):
        self.addr = addr
        if op is not None:
            assert len(data) == op.size
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

    def __repr__(self):
        if self._str is None:
            if self.op is None:
                self._str = '[0x%x] %-12s' % \
                        (self.addr, self.data.hex(' '))
            else:
                self._str = '[0x%x] %-12s  %s' % \
                        (self.addr, self.data.hex(' '), self.op)
        return self._str

    @property
    def size(self):
        return len(self.data)


class BLOCK:
    def __init__(self, idx, lines=None):
        self.idx = idx
        self._col = None

        if lines is None:
            self.lines = []
        else:
            self.lines = lines

        self.links = {}

    def __repr__(self):
        return 'BLOCK%d(0x%x, 0x%x)' % (self.idx, self.start, self.end)

    def __iter__(self):
        return iter(self.lines)

    def __getitem__(self, idx):
        return self.lines[idx]

    @property
    def width(self):
        return max(l.width for l in self.lines)

    def add(self, line):
        self.lines.append(line)

    def __len__(self):
        return sum(l.size for l in self.lines)

    @property
    def start(self):
        return self.lines[0].addr

    @property
    def last_line(self):
        return self.lines[-1]

    @property
    def end(self):
        return self.last_line.addr + self.last_line.size

    def __contains__(self, addr):
        return addr >= self.start and addr < self.end

    def split_at(self, addr):
        for idx, line in enumerate(self.lines):
            if line.addr == addr:
                break
        else:
            raise IndexError('address 0x%x not found in block %d (0x%x - 0x%x)' %
                    (addr, self.idx, self.start, self.end))

        new_block_lines = self.lines[:idx]
        self.lines = self.lines[idx:]

        # Make a new block using the old index, and the updated old block index as
        # the only target (because it should be a simple fall through instruction)
        new_block = BLOCK(idx=self.idx, lines=new_block_lines)

        # Now update the this block's index
        self.idx += 1

        # return the new block
        return new_block

    @property
    def col(self):
        return self._col

    @col.setter
    def col(self, value):
        self._col = value

    def add_link(self, addr, dest=None):
        assert dest is None or isinstance(dest, BLOCK)
        if addr in self.links:
            link = self.links[addr]

            # Update destination
            link.dest = dest
        else:
            link = LINK(self, addr, dest)
            self.links[addr] = link
        return link

    def link(self, addr):
        if addr not in self.links:
            return None
        else:
            return self.links[addr]

    def target(self, addr):
        return self.links[addr].dest


class LINK:
    def __init__(self, src, addr, dest=None, col=None):
        self.addr = addr
        self.src = src
        self.dest = dest

        # Set the column for this link
        self.col = col

    def __contains__(self, block):
        if isinstance(block, BLOCK):
            block = block.idx

        # Indicate if the specified block ID falls within this link's source and
        # destination
        contains = False
        if self.forwards and self.src.idx <= block and self.dest.idx > block:
            contains = True
        elif self.backwards and self.src.idx >= block and self.dest.idx <= block:
            contains = True
        return contains

    def __repr__(self):
        if self.addr is None:
            return '%d -> None' % self.src.idx
        elif self.dest is None:
            return '%d -> 0x%x (None)' % (self.src.idx, self.addr)
        else:
            return '%d -> 0x%x (%d[%s])' % (self.src.idx, self.addr, self.dest.idx, self.col)

    @property
    def col(self):
        # If this is a forward link the "column" for the link is the column of
        # the destination. If this is a backwards link it has it's own column.
        if self.forwards:
            return self.dest.col
        else:
            return self._col

    @col.setter
    def col(self, value):
        # If this is a forward link the "column" for the link is the column of
        # the destination. If this is a backwards link it has it's own column.
        if value is not None and self.dest is not None and value >= 0:
            self.dest.col = value
        else:
            self._col = value

    @property
    def valid(self):
        return self.dest is not None

    @property
    def backwards(self):
        return self.valid and self.dest.idx <= self.src.idx

    @property
    def forwards(self):
        return self.valid and self.dest.idx > self.src.idx


class LINK_LIST:
    def __init__(self):
        self.links = []

    def __getitem__(self, idx):
        return self.links[idx]

    def __iter__(self):
        return iter(self.links)

    def __contains__(self, target):
        return any(l.dest == idx if l.valid else False for l in self.links)

    def add(self, src, addr, dest=None):
        link = src.add_link(addr, dest)

        # Track this link
        if link not in self.links:
            self.links.append(link)

    def find_dest(self, dest):
        return [l for l in self.links if l.dest is dest]

    def find_active(self, idx):
        # Return the links active at any particular block, this does not include
        # links that are only draw between two sequential blocks
        for link in self.links:
            if idx in link and link.dest.col is not None:
                yield link


class BLOCK_LIST:
    def __init__(self, blocks=None):
        if blocks is None:
            self.blocks = []
        elif isinstance(blocks, (list, tuple)):
            self.blocks = list(blocks)
        elif isinstance(blocks, BLOCK):
            self.blocks = [blocks]
        else:
            raise TypeError('Cannot initialize BLOCK_LIST with blocks: %s' % repr(blocks))

        self.links = LINK_LIST()

    def __getitem__(self, idx):
        return self.blocks[idx]

    def __contains__(self, idx):
        return len(self.blocks) > idx

    def __iter__(self):
        return iter(self.blocks)

    def add(self, block):
        self.blocks.append(block)

    def split_block(self, idx, addr):
        if isinstance(idx, BLOCK):
            idx = idx.idx

        # Before splitting the block, go through the blocks update the block
        # index for all blocks > the target index.
        for block in self.blocks:
            if block.idx > idx:
                block.idx += 1

        # Find the target block and split it into two parts
        block = self.blocks[idx]
        old_block_str = str(block)
        new_block = block.split_at(addr)

        # Now insert the new block
        self.blocks.insert(idx, new_block)

        # Find any links to the old block and move them the new block, the old
        # block should not have any links to it yet.
        for link in self.links:
            if link.valid and link.dest == block:
                link.dest = new_block

        # Automatically add a link from the new block to the old block
        self.add_link(new_block, block.start, block.idx)

        # Return the id of the block that now contains the address
        return idx + 1

    def finalize(self):
        # Remove the last block (it should be empty) or just be garbage data
        if len(self.blocks[-1]) != 0:
            # All of the lines in this block should be data with no instruction
            if not all(l.op is None for l in self.blocks[-1]):
                for line in self.blocks[-1]:
                    print(line)
                raise Exception

        self.blocks.pop()

        # Check that all of the blocks have lines and that the indexes match up
        # correctly
        assert all(len(b) > 0 for b in self.blocks)
        assert all(b.idx == i for i, b in enumerate(self.blocks))

        # Now go find the link targets to complete finalization of the block
        # list
        self.identify_link_targets()

        # Assign blocks to columns for display
        self.allocate_columns()

        # Find the width of the right column padding
        self.col_width = max(b.width for b in self.blocks)

        # Find the maximum column for the forward links and the minimum column
        # for the backwards links
        max_forwards_col = 0
        max_backwards_col = 0
        for link in self.links:
            if link.forwards:
                max_forwards_col = max(max_forwards_col, link.col)
            elif link.backwards:
                max_backwards_col = max(max_backwards_col, abs(link.col))

        # The right columns includes column 0
        self.num_right_cols = max_forwards_col + 1
        self.num_left_cols = max_backwards_col
        self.columns = range(-self.num_left_cols, self.num_right_cols)

        # And ensure that all blocks have been correctly allocated a column, if
        # not then just place it in column 0
        for block in self.blocks:
            if block.col is None:
                block.col = 0

    def add_link(self, src, addr, dest):
        if isinstance(src, BLOCK):
            block = src
        else:
            block = self.blocks[src]

        if dest is not None:
            if isinstance(dest, BLOCK):
                self.links.add(block, addr, dest)
            else:
                self.links.add(block, addr, self.blocks[dest])
        else:
            self.links.add(block, addr)

    def get_active_links(self, block):
        if isinstance(block, BLOCK):
            links = list(self.links.find_active(block.idx))
        else:
            links = list(self.links.find_active(block))
        return links

    def get_columns(self, block):
        if isinstance(block, BLOCK):
            block = block.idx

        columns = dict((c, []) for c in self.columns)
        for col in self.columns:
            for link in self.get_active_links(block):
                if link not in columns[link.col]:
                    columns[link.col].append(link)

        return columns

    def identify_link_targets(self):
        # Identify the targets for each block, and split target blocks if
        # necessary
        idx = 0
        while True:
            src = self.blocks[idx]
            for addr, link in src.links.items():
                # If the target address is None, or destination has already
                # been identified, there is nothing to do here
                if addr is None or link.valid:
                    continue

                try:
                    dest = next(b for b in self.blocks if addr == b.start)
                    self.add_link(idx, addr, dest)

                except StopIteration:
                    # target address is not the start of a block, try to find a
                    # block that contains the target address
                    try:
                        block = next(b for b in self.blocks if addr in b)

                        # Split the target block and get the index of the new
                        # block
                        dest = self.split_block(block, addr)

                        # Now make a link to the new block
                        self.add_link(src, addr, dest)

                    except StopIteration:
                        # Can't find a target, so just leave the destination
                        # as-is (None)
                        pass

            # Increment to the next block, looping this way so the block list
            # can be modified as we loop.
            idx += 1
            if idx >= len(self.blocks):
                break

    def find_link_sources(self, block):
        return [l.src for l in self.links.find_dest(block)]

    def allocate_columns(self):
        # Start block 0 in column 0
        self.blocks[0].col = 0

        # Loop through every block and assign it's targets a column
        for block in self.blocks:
            # If this block is the destination in any of the active links,
            # remove them from the active links list now.
            for link in block.links.values():
                # If the target is not valid (no destination block was found) or the
                # target already has a column assigned,
                if not link.valid or link.col is not None:
                    continue

                active_links = self.get_active_links(block)
                if link.forwards:
                    # find the first available column for this link
                    used_cols = [l.col for l in active_links if l.forwards and l.col is not None]
                    if used_cols:
                        link.col = next(i for i in range(max(used_cols)+2) if i not in used_cols)
                    else:
                        link.col = 0

                else:
                    # find the first available backwards column for this link
                    used_cols = [l.col for l in active_links if l.backwards and l.col is not None]
                    if used_cols:
                        link.col = next(i for i in range(min(used_cols)-1) if i not in used_cols)
                    else:
                        link.col = -1


def decode_lines(in_file, va=0, arch=None, vle=False, offset=0, size=None):
    _, emu = vwopen(arch)

    with open(in_file, 'rb') as f:
        f.seek(offset)
        if end is None:
            firmware = f.read()
        else:
            firmware = f.read(size)

        file_offset = 0
        while file_offset < len(firmware):
            try:
                if firmware[file_offset:file_offset+4] == b'\xff\xff\xff\xff':
                    raise Exception()
                op = decode(emu, firmware, vle, offset=file_offset, va=va+file_offset, verbose=False)
                incr = op.size
            except:
                op = None
                incr = 2 if vle else 4

            data = firmware[file_offset:file_offset+incr]
            yield LINE(va+file_offset, data, op)

            file_offset += incr


def decode_blocks(in_file, va=0, arch=None, vle=False, offset=0, size=None):
    # A Block is a tuple of (lines, next_blocks).  None in place of the next
    # block list indicates
    idx = 0
    blocks = BLOCK_LIST()
    blocks.add(BLOCK(idx))

    lines = list(decode_lines(in_file, va=va, arch=arch, vle=vle, offset=offset, size=size))
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
                line.comment = '    ; CALL ' + filename
            else:
                line.comment = '    ; CALL'

        # Add this instruction to the current block
        blocks[idx].add(line)

        # If this instruction branches or returns, this is the end of a
        # block
        if TGT_TYPE.BRANCH in tgts or TGT_TYPE.RET in tgts:
            # First add the fallthrough link
            if TGT_TYPE.FALL in tgts:
                blocks.add_link(idx, tgts[TGT_TYPE.FALL], None)

            # Just use the address at the moment since we don't know which block
            # this will be. Identify the targets of this block.
            if TGT_TYPE.BRANCH in tgts:
                blocks.add_link(idx, tgts[TGT_TYPE.BRANCH], None)
            else:
                # The return target should be None, but just use the value
                # provided
                blocks.add_link(idx, tgts[TGT_TYPE.RET], None)

            # Now start a new block
            idx += 1
            blocks.add(BLOCK(idx))

    blocks.finalize()
    return blocks


_right_link = None
_right_pad = None
_left_link = None
_left_pad = None


def draw_links(columns, block):
    # Only draw columns which don't includes the destination links for the
    # current block (if that column is only the current block)
    cols = dict((c, []) for c in columns)
    for link in sum((l for l in columns.values()), []):
        if link.forwards and link.src is not block:
            cols[link.col].append(link)
        elif link.backwards:
            cols[link.col].append(link)

    global _right_link, _right_pad, _left_link, _left_pad

    # Draw the backwards links
    left = ''.join(_left_link if l else _left_pad for l in \
            (l for c, l in cols.items() if c < 0))

    # Now add any block indentation
    left += ''.join(_right_link if l else _right_pad for l in \
            (l for c, l in cols.items() if c in range(0, block.col)))

    # Now draw any forwards links
    right = ''.join(_right_link if l else _right_pad for l in \
            (l for c, l in cols.items() if c > block.col))

    return left, right


def draw_src_links(columns, block):
    # Draw the links in the source block column if the current block is the
    # source, only bother filling in the forward links here.
    src_cols = dict((c, []) for c in columns)
    for link in sum((l for l in columns.values()), []):
        if link.forwards:
            if link.src is block and link.dest.idx == link.src.idx + 1:
                src_cols[link.src.col].append(link)
            else:
                src_cols[link.col].append(link)
        elif link.backwards and link.src.idx > block.idx and link.dest.idx <= block.idx:
            # Only add backwards links if the source is < the current block and
            # the dest is > the current block
            src_cols[link.col].append(link)

    global _right_link, _right_pad, _left_link, _left_pad
    # Draw the backwards links
    line = ''.join(_left_link if l else _left_pad for l in \
            (l for c, l in src_cols.items() if c < 0))

    # Draw all columns in one line
    line += ''.join(_right_link if l else _right_pad for l in \
            (l for c, l in src_cols.items() if c >= 0))

    return line.rstrip()


def draw_transition_links(columns, block):
    global _right_link, _right_pad, _left_link, _left_pad
    # Draw the backwards links, but only backwards links that where the src
    # block is > the current block
    left = ''.join(_left_link if links and any(l.src.idx > block.idx for l in links) else _left_pad for links in \
            (links for c, links in columns.items() if c < 0))

    # Draw the normal columns
    right = ''.join(_right_link if l else _right_pad for l in \
            (l for c, l in columns.items() if c >= 0))

    # Find the destination block column
    links = sum((l for l in columns.values()), [])

    # Identify the longest src->dest line that needs to be drawn
    left_col = None
    right_col = None
    connect_cols = []
    for link in links:
        # If the source block is the current block and the destination block is
        # the next block
        if link.src is block and link.dest.idx == block.idx + 1:
            connect_cols.append(link.src.col)
            if link.src.col < link.dest.col:
                left_col = link.src.col
                right_col = link.dest.col
            if link.src.col > link.dest.col:
                left_col = link.dest.col
                right_col = link.src.col

    if left_col == right_col:
        # If the left and right columns are the same, don't bother returning
        # anything
        return None

    # Find the start and end offsets of the connecting line
    connect_offset = _right_link.index('|')
    start = (len(_right_link) * left_col) + connect_offset
    end = (len(_right_link) * right_col) + connect_offset

    src_to_dest_line = '-' * (end - start)
    right = right[:start] + src_to_dest_line + right[end:]

    # Add all of the columns connectors "+" in now
    connect_cols.append(left_col)
    connect_cols.append(right_col)
    for col in connect_cols:
        off = (len(_right_link) * col) + connect_offset
        right = right[:off] + '+' + right[off+1:]

    return (left + right).rstrip()


def draw_dest_links(columns, block):
    global _right_link, _right_pad, _left_link, _left_pad
    # Draw the backwards links
    line = ''.join(_left_link if links and any(l.src.idx > block.idx for l in links) else _left_pad for links in \
            (links for c, links in columns.items() if c < 0))

    # Draw the links replacing the "|" link with the "v" destination indicator,
    # and draw all columns in one line
    for col, links in columns.items():
        if col >= 0:
            if links:
                if any(l.dest.idx == block.idx+1 for l in links):
                    line += _right_link.replace('|', 'v')
                else:
                    line += _right_link
            else:
                line += _right_pad

    return line.rstrip()


def decode_file(in_file, out_file=None, va=0, arch=None, vle=False, fancy=False, print_block_headers=False, offset=0, size=None):
    if arch is None:
        arch = 'ppc32-embedded'

    if out_file is None:
        outfd = sys.stdout
    else:
        outfd = open(out_file, 'w')

    blocks = decode_blocks(in_file, va=va, arch=arch, vle=vle, offset=offset, size=size)

    if fancy:
        global _right_link, _right_pad, _left_link, _left_pad
        _right_link = ' |' + (' ' * (blocks.col_width-2))
        _right_pad = ' ' * blocks.col_width

        _left_link = '  ‖  '
        _left_pad = ' ' * len(_left_link)

        right_connect_offset = _right_link.index('|')
        left_connect_offset = _left_link.index('‖')
        max_left_width = len(_left_link) * blocks.num_left_cols

    for block in blocks:
        if fancy:
            columns = blocks.get_columns(block)

            # Get the link targets for this block
            targets = list(block.links.values())

            # create any link strings for the last line in the block

            left, right = draw_links(columns, block)

            # If there is a reverse link that ends at this block, calculate the
            # start and end of the connecting line.
            left_connect = ''
            for col in range(-blocks.num_left_cols, 0):
                links = columns[col]
                if any(l.dest.idx == block.idx for l in links):
                    left_start = max_left_width - (len(_left_link) * abs(col)) + left_connect_offset
                    left_end = max_left_width + (len(_right_link) * (block.col))
                    left_connect = '+' + ('-' * (left_end - left_start - 2)) + '>'

            if print_block_headers:
                block_str = '%s %d: %s' % (block, block.col, ', '.join('%d[%d]' % (l.col, l.dest.idx) if l.dest else 'None' for l in block.links.values()))
                line_pad = ' ' * (blocks.col_width - len(block_str))
                out = (left + block_str + line_pad + right).rstrip()

                # If the header is being printed and there is a left column
                # connection, add that in now
                if left_connect:
                    out = out[:left_start] + left_connect + out[left_end:]

                print(out, file=outfd)

        for line in block:
            if fancy:
                line_pad = ' ' * (blocks.col_width - line.width)
                out = left + str(line)
                comment_offset = len(out)
                out = (out + line_pad + right).rstrip()

                out = out[:comment_offset] + line.comment + out[comment_offset+len(line.comment):]

                if line == block[-1]:
                    # If this is the last line and there is a non-fallthrough
                    # link, draw it out now.
                    for link in block.links.values():
                        if link.forwards and link.dest.idx != block.idx + 1:
                            if link.col > block.col:
                                start = comment_offset + len(line.comment)
                                col_width = link.col - block.col
                                end = len(left) + (len(_right_link) * col_width) + right_connect_offset
                                connect = ' ' + ('-' * (end - start - 1)) + '+'
                                out = out[:start] + connect + out[end+1:]
                            elif link.col < block.col:
                                start = max_left_width + (len(_right_link) * link.col) + right_connect_offset
                                end = len(left)
                                connect = '+' + ('-' * (end - start - 1))
                                out = out[:start] + connect + out[end:]
                        elif link.backwards:
                            end = max_left_width + (len(_right_link) * (block.col))
                            start = max_left_width - (len(_left_link) * abs(link.col)) + left_connect_offset
                            connect = '+' + ('-' * (end - start - 1))
                            out = out[:start] + connect + out[end:]
                elif line == block[0] and not print_block_headers and left_connect:
                    # If this is the first line in a block and the block header
                    # isn't printed and there is a reverse link that ends at
                    # this block, add the connecting link.
                    out = out[:left_start] + left_connect + out[left_end:]

            else:
                out = str(line)
                if line.comment:
                    comment_offset = len(out)
                    out = out[:comment_offset] + line.comment + out[comment_offset+len(line.comment):]

            print(out, file=outfd)

        # Print the between block lines, unless this is the last block of the
        # procedure or the last block of a backwards link
        if fancy and block is not blocks.blocks[-1]:
            # Now draw some src to dest links and move the src links into
            # the dest column
            out_lines = [
                draw_src_links(columns, block),
                draw_transition_links(columns, block),
                draw_dest_links(columns, block),
            ]

            for out in out_lines:
                if out is not None:
                    print(out, file=outfd)

    if outfd != sys.stdout:
        outfd.close()


def main():
    ppc_arch_list = [n for n in envi.arch_names.values() if n.startswith('ppc')]

    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='file to dump instructions from')
    parser.add_argument('-v', '--vle', action='store_true', help='Decode instructions as VLE')
    parser.add_argument('-a', '--arch', default='ppc32-embedded', choices=ppc_arch_list)
    parser.add_argument('-b', '--baseaddr', default='0x00000000')
    parser.add_argument('-o', '--offset', default='0x00000000')
    parser.add_argument('-s', '--size', nargs='?', const=None)
    parser.add_argument('-f', '--fancy', action='store_true')
    parser.add_argument('-B', '--print-block-headers', action='store_true')
    args = parser.parse_args()

    va = int(args.baseaddr, 0)
    offset = int(args.offset, 0)

    if args.size is not None:
        size = int(args.size, 0)
    else:
        size = None

    decode_file(args.filename, va=va, arch=args.arch, vle=args.vle,
                fancy=args.fancy, print_block_headers=args.print_block_headers,
                offset=offset, size=size)

if __name__ == '__main__':
    main()
