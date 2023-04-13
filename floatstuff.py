import struct


def single_info(val, verbose=True):
    if isinstance(val, int):
        iee1754_val = val
        exp = (iee1754_val & 0x7F80_0000) >> 23
        frac = iee1754_val & 0x007F_FFFF
        result = struct.unpack('>f', struct.pack('>I', iee1754_val))[0]

    elif isinstance(val, float):
        result = val
        iee1754_val = struct.unpack('>I', struct.pack('>f', result))[0]
        exp = (iee1754_val & 0x7F80_0000) >> 23
        frac = iee1754_val & 0x007F_FFFF

    if verbose:
        print('Single Precision:')
        print('%08x: %03x %05x' % (iee1754_val, exp, frac))
        print('%.60f' % result)
    return (result, (iee1754_val, exp, frac))

def double_info(val, verbose=True):
    if isinstance(val, int):
        iee1754_val = val
        exp = (iee1754_val & 0x7FF0_0000_0000_0000) >> 52
        frac = iee1754_val & 0x00F_FFFF_FFFF_FFFF
        result = struct.unpack('>d', struct.pack('>Q', iee1754_val))[0]

    else:
        iee1754_val = struct.unpack('>Q', struct.pack('>d', val))[0]
        exp = (iee1754_val & 0x7FF0_0000_0000_0000) >> 52
        frac = iee1754_val & 0x00F_FFFF_FFFF_FFFF
        result = (2**(exp-1023)) * (1+(frac/(2**52)))

    if verbose:
        print('Double Precision:')
        print('%016x: %03x %05x' % (iee1754_val, exp, frac))
        print('%.60f' % result)
    return (result, (iee1754_val, exp, frac))
