"""
Module for enforcement of aligned execution
"""

import os
import sys
import config
from itertools import imap
from termcolor import colored
from utils.ail_utils import ELF_utils
from postprocess import compile_process
from elftools.elf.elffile import ELFFile


if ELF_utils.elf_arm():

    def get_hex():
        """
        Get byte encodings corresponding to each source code line
        """
        f = open('a.out', 'rb')
        info = ELFFile(f)
        dwarf = info.get_dwarf_info()
        cu = next(dwarf.iter_CUs())
        lp = dwarf.line_program_for_CU(cu).get_entries()

        textsec = info.get_section_by_name('.text')
        datas = filter(lambda s: s.name == '$d', info.get_section_by_name('.symtab').iter_symbols())
        datas = sorted(map(lambda s: s.entry['st_value'], datas))
        datas = filter(lambda s: lp[0].args[0] < s < lp[-1].state.address, datas)
        datas.append(0)
        voff = textsec.header['sh_addr'] - textsec.header['sh_offset']

        curr_line = 0; curr_data = 0; update_line = False
        res = [''] * (lp[-1].state.line + 1)
        f.seek(lp.pop(0).args[0] - voff, os.SEEK_SET)

        for e in lp:
            if update_line:
                curr_line = e.state.line - 1
                update_line = False
            if len(e.args) == 0:
                curr_line = e.state.line - 1
            elif len(e.args) == 1:
                pc = voff + f.tell()
                if pc < datas[curr_data] <= pc + e.args[0]:
                    size = datas[curr_data] - pc
                    res[curr_line] += f.read(size)
                    f.seek(e.args[0] - size, os.SEEK_CUR)
                    while pc < datas[curr_data] < pc + e.args[0]: curr_data += 1
                    update_line = True
                else:
                    res[curr_line] += f.read(e.args[0])
            elif len(e.args) > 1:
                pc = voff + f.tell()
                if pc < datas[curr_data] < pc + e.args[1]:
                    size = datas[curr_data] - pc
                    res[curr_line] += f.read(size)
                    f.seek(e.args[1] - size, os.SEEK_CUR)
                    curr_line = e.state.line - 1
                    while pc < datas[curr_data] < pc + e.args[1]: curr_data += 1
                elif e.args[0] == 0:
                    f.seek(e.args[1], os.SEEK_CUR)
                    curr_line = e.state.line - 1
                else:
                    res[curr_line] += f.read(e.args[1])
                    curr_line += e.args[0]
        f.close()
        return res

    badbytes = set(('\xbd', '\x47', '\5d'))
    sled = '; mov r0,r0\n'

    def sled_insertion(fixed):  # @UnusedVariable
        """
        Insert alignment enforcing sleds
        """
        hexvals = get_hex()
        nmodified = 0

        with open('final.s') as f:
            lines = f.readlines()

        for i in xrange(len(hexvals)-1):
            hv0 = hexvals[i]
            if not lines[i].endswith(sled) and hv0:
                hv1 = next((hexvals[j] for j in xrange(i+1, len(hexvals)) if hexvals[j]), '')
                if len(hv1) > 3 and hv1[3] in badbytes:
                    lines[i] = lines[i].replace('\n', sled)
                    nmodified += 1

        with open('final.s', 'w') as f:
            f.writelines(lines)

        return nmodified > 0

else:

    def get_hex():
        """
        Get byte encodings corresponding to each source code line
        """
        f = open('a.out', 'rb')
        info = ELFFile(f)
        dwarf = info.get_dwarf_info()
        cu = next(dwarf.iter_CUs())
        lp = dwarf.line_program_for_CU(cu).get_entries()

        textsec = info.get_section_by_name('.text')
        voff = textsec.header['sh_addr'] - textsec.header['sh_offset']

        curr_line = 0
        res = [''] * (lp[-1].state.line + 1)
        f.seek(lp.pop(0).args[0] - voff, os.SEEK_SET)

        for e in lp:
            if len(e.args) == 0:
                curr_line = e.state.line - 1
            elif len(e.args) == 1:
                res[curr_line] += f.read(e.args[0])
            elif len(e.args) > 1:
                if e.args[0] == 0:
                    f.seek(e.args[1], os.SEEK_CUR)
                    curr_line = e.state.line - 1
                else:
                    res[curr_line] += f.read(e.args[1])
                    curr_line += e.args[0]
        f.close()
        return res

    badbytes = set(('\xc2', '\xc3', '\xca', '\xcb'))
    badend = set(('\xff'))
    branchenc = set(('\x72', '\x76', '\xe3', '\x7c', '\x7e', '\xe9', '\xeb', '\x73',
                     '\x77', '\x7d', '\x7f', '\x71', '\x7b', '\x79', '\x75', '\x70',
                     '\x7a', '\x78', '\x74'))
    sled = 'jmp .+11;' + ('nop;' * 9) + ' '
    barrier = '; mov %eax,%eax\n' if ELF_utils.elf_32() else '; mov %rax,%rax\n'
    indcodes = set((2,3,4,5))

    def sled_insertion(fixed):
        """
        Insert alignment enforcing sleds
        :param fixed: set of lines already fixed
        """
        hexvals = get_hex()
        nmodified = 0

        with open('final.s') as f:
            lines = f.readlines()

        for i in xrange(len(hexvals)):
            hv = hexvals[i]
            if i not in fixed and hv:
                if hv[-1] in badend:
                    hv1 = next((hexvals[j] for j in xrange(i+1, len(hexvals)) if hexvals[j]), '\x00')
                    if ((ord(hv1[0]) >> 3) & 0b111) in indcodes:
                        lines[i] = lines[i].replace('\n', barrier)
                        nmodified += 1
                if hv[0] in branchenc and hv[1] in badbytes:
                    lines[i-1] = lines[i-1].replace('\n', ';nop\n')
                    lines[i] = lines[i].replace('\n', ';nop\n')
                elif hv[0] != '\xf3' and any(imap(lambda b: b in badbytes, hv[1:])):
                    lines[i] = sled + lines[i]
                    fixed.add(i)

        with open('final.s', 'w') as f:
            f.writelines(lines)

        return nmodified > 0


def enforce_alignment():
    """
    Apply alignment enforcement inserting sleds in assembler source code
    """
    print colored('6: ALIGNMENT ENFORCEMENT', 'green')
    npass = 0
    fixed = set()
    while npass < config.gfree_maxalignmentpass:
        sys.stdout.write('\r     Passes: %d' % (npass+1))
        sys.stdout.flush()
        compile_process.main(debug=True)
        if not sled_insertion(fixed): break
        npass += 1
    sys.stdout.write('\n')
