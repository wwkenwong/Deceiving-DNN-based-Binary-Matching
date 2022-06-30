"""
Compile assembly source
"""

import os
import re
import config
from utils.ail_utils import ELF_utils


def inferlibflags():
    """
    Infer linked libraries from original executable elf info
    """
    try:
        with open('linkedlibs.info') as f:
            return map(lambda l: '-l' + l.split('.')[0].lstrip('lib'), f)
    except: return []


def reassemble(saveerr=False, libs=[], debug=False):
    """
    Invoke compiler
    :param saveerr: True to store compilation error to file
    :param libs: list of linked libraries
    :param debug: True to compile with debug symbols
    """
    if len(libs) == 0: libs = inferlibflags()
    return os.system(config.compiler + ' final.s '
              + ('-g ' if debug else '')
              + ('-mthumb' if ELF_utils.elf_arm() else (' -Wa,-mindex-reg' + (' -m32' if ELF_utils.elf_32() else '')))
              + ' ' + config.gccoptions + ' ' + ' '.join(libs)
              + (' 2> final.error' if saveerr else ''))


def parse_error():
    """
    Find undefined label errors
    """
    if os.path.isfile('final.error'):
        addrs = []
        with open("final.error") as ferror:
            for l in ferror:
                if 'In function' in l: pass
                elif 'undefined reference' in l and 'S_0x' in l:
                    addrs.append(l.split()[-1][1:-1])
        return set(addrs)


def modify(errors):
    """
    Correct undefined labels
    """
    if len(errors) == 0: return
    with open("final.s") as f:
        lines = f.readlines()
    def help_err(l):
        e = filter(lambda e : e in l, errors)
        if e != []:
            addr = e[0][2:]
            #print "undefined label : "+addr
            l = l.replace(e[0], addr)
        return l
    lines = map(help_err, lines)
    with open("final.s", 'w') as f:
        f.writelines(lines)

def adjusttbb(pos):
    """
    Routine to fix tbb value overflow
    :param pos: error line number
    """
    i = 0
    pos.sort()
    with open('final.s') as f:
        lines = f.readlines()
    while i < len(pos):
        c = pos[i] - 1
        while 'tbb' not in lines[c]: c -= 1
        lines[c] = lines[c].replace('tbb', 'tbh', 1).replace(']', ',lsl #1]', 1)
        while '.byte (' not in lines[c]: c += 1
        while '.byte (' in lines[c]:
            lines[c] = lines[c].replace('.byte', '.short', 1)
            if i < len(pos) and c == pos[i]: i += 1
            c += 1
    with open('final.s', 'w') as f:
        f.writelines(lines)

def badinstrmapper(bad):
    """
    Get routine to delete bad instructions
    :param bad: bad instruction string
    """
    def mapper(line):
        return line.replace(bad, '')
    return mapper

def cbzmapper():
    """
    Get routine to translate out of range cbz
    """
    cbzpatt = re.compile('([^\:]+\s*\:\s*)?(cbn?z)\s+([^,]+),([^\n]+)', re.I)
    def mapper(line):
        m = cbzpatt.match(line)
        if not m: return line
        items = list(m.groups())
        if items[0] is None: items[0] = ''
        items[1] = 'ne' if len(items[1]) > 3 else 'eq'
        return '{0}cmp {2},#0\nb{1} {3}\n'.format(*items)
    return mapper

def outofrangemapper():
    """
    Get routing to translate out of range vldr
    """
    oorpatt = re.compile('([^\:]+\s*\:\s*)?vldr\s+([^,]+),(S_0x[A-F0-9]+)', re.I)
    def mapper(line):
        m = oorpatt.match(line)
        if not m: return line
        items = list(m.groups())
        if items[0] is None: items[0] = ''
        return '''{0}push {{r0}}
movw r0,#:lower16:{2}
movt r0,#:upper16:{2}
vldr {1},[r0]
pop {{r0}}
'''.format(*items)
    return mapper

def modifyARM():
    """
    Fix errors:
    - branch out of range
    - selected processor does not support `XXX' in Thumb mode
    - too large for field
    - co-processor offset out of range
    """
    reassemble(True)
    if not os.path.isfile('final.error'): return True
    with open('final.error') as f:
        lines = f.readlines()
    cbz = filter(lambda l: 'branch out of range' in l, lines)
    bad = filter(lambda l: 'processor does not support' in l, lines)
    tbb = filter(lambda l: 'too large for field of 1 bytes at' in l, lines)
    outrange = filter(lambda l: 'co-processor offset out of range' in l, lines)
    if sum(map(len, (cbz, bad, tbb, outrange))) == 0: return True
    patt = re.compile('final\.s\:([0-9]+)\:', re.I)
    errors = {}
    if len(cbz) > 0:
        cbz = map(lambda l: int(patt.match(l).group(1))-1, cbz)
        for c in cbz:
            errors[c] = cbzmapper()
    if len(bad) > 0:
        bpatt = re.compile("final\.s\:([0-9]+)\:[^`]+`([^']+)'", re.I)
        bad = map(lambda l: bpatt.match(l).groups(), bad)
        for b in bad:
            errors[int(b[0])-1] = badinstrmapper(b[1])
    if len(outrange) > 0:
        outrange = map(lambda l: int(patt.match(l).group(1))-1, outrange)
        for o in outrange:
            errors[o] = outofrangemapper()
    if len(tbb) > 0:
        tbb = map(lambda l: int(patt.match(l).group(1))-1, tbb)
        adjusttbb(tbb)
    with open('final.s') as f:
        lines = f.readlines()
    for c in sorted(errors.keys()):
        lines[c] = errors[c](lines[c])
    with open('final.s', 'w') as f:
        f.writelines(lines)

    return False


def main(filepath='', libs=[], debug=False):
    """
    Compile recovered assembler source and fix some errors
    :param filepath: original executable filepath
    :param libs: list of linked libraries
    :param debug: True to compile with debug symbols
    """
    if filepath:
        # Dump linked shared libraries
        os.system('readelf -d ' + filepath + ' | awk \'/Shared/{match($0, /\[([^\]]*)\]/, arr); print arr[1]}\' | grep -i -v "libc\\." > linkedlibs.info')
        print "     Applying adjustments for compilation"
    if ELF_utils.elf_arm():
        i = 0
        while not modifyARM() and i < 10: i += 1
    reassemble(True, libs, debug)
    errors = parse_error()
    modify(errors)
