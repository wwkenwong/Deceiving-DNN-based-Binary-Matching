"""
ARM executable disassembler
"""

import re
import capstone
from struct import unpack
from elftools.elf.elffile import ELFFile


def load_size(op, exp):
    """
    Return byte size of the memory load
    :param op: load operator string
    :param exp: load expression string
    :return: size of loaded data
    """
    op = op.lower()
    if op.startswith('vldr'):
        return 4 if exp.startswith('s') else 8
    if op.startswith('ldr'):
        if len(op) < 4 or op[3] == '.': return 4
        if op[3] == 'd': return 8
        if op[3] == 'h' or (op[3] == 's' and op[4] == 'h'): return 2
        return 1
    return 4

def tb_process(offsize, pc, buf, filehandle):
    """
    Manage tb[hb] jumptable
    :param offsize: jump table entry size
    :param pc: current program counter
    :param buf: raw data containing jump offsets
    :param filehandle: file handle for code dump
    """
    i = 0
    unpacker = '<H' if offsize == 2 else '<B'
    datatype = ('.short' if offsize == 2 else '.byte').ljust(7)
    while i < len(buf):
        val = unpack(unpacker, buf[i:i+offsize])[0] << 1
        filehandle.write(('%x' % (pc+i)).rjust(8) + ':\t' + datatype + ' (S_0x%X-S_0x%X)/2\n' % ((pc + val) & 0xFFFFFFFF, pc))
        i += offsize

def eval_tb_size(op, last_cmp, reg):
    """
    Evaluate jump table size
    :param op: jump table operator
    :param last_cmp: last compare operation
    :param reg: jump table index register
    :return: tuple of jump table entry size and byte size of table
    """
    if reg != last_cmp[0]: raise Exception('Unhandled jumptable case')
    offsize = 4 if op.startswith('ldr') else (2 if op[-1] == 'h' else 1)
    tablesize = (int(last_cmp[1].strip()[1:], 16) + 1) * offsize
    tablesize += (tablesize & 1) # For 2 byte alignment
    return (offsize, tablesize)

def arm_process(filename):
    """
    Disassemble the binary processing PC relative loads
        ldr.w   ip, [pc, #16]
    library function invokations
        blx     #0x10a40 <strcmp@plt>
    inline jump tables
        tbh     [pc, r3, lsl #1]
         .short  0x0123
          ...
     or
        add     r2, pc, #4
        ldr     pc, [r2, r3, lsl #2]
         .word   0x00010545
         ...
    :param filename: path to target executable
    """

    # Open ELF executable, read info and read raw binary .text section
    with open(filename, 'rb') as f:
        raw = f.read()
        f.seek(0)
        textsec = ELFFile(f).get_section_by_name('.text')
        textsec.addr = textsec.header['sh_addr']
        textsec.size = textsec.header['sh_size']
        textsec.offset = textsec.header['sh_offset']

    textraw = raw[textsec.offset : textsec.offset + textsec.size]
    with open('plts.info') as f:
        plts = {int(l.split()[0],16): ' ' + l.split()[1].rstrip(':') for l in f}

    dis = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    dis.syntax = capstone.CS_OPT_SYNTAX_ATT

    inlinedata = {}
    negpcrel = False
    secondpass = True
    last_cmp = ('', '')
    last_adr_dest = 0
    last_adr_reg = None
    pcrelre = re.compile('\[pc,\s*\#(\-?0x[0-9a-f]+)\]', re.I)
    pcreltblre = re.compile('\[pc,\s*(r[0-9]+)(,\s*lsl \#1)?\]|pc,\s*\[r[0-9]+,\s*(r[0-9]+|fp|lr|sb|sl),\s*lsl\s*\#2\]', re.I)
    pcreladdre = re.compile('^(r[0-9]+|fp|lr|sb|sl),\s*pc,\s*\#(0x[0-9a-f]+)$', re.I)
    baseregre = re.compile('\[([^,]+),?.*\]', re.I)
    calls = set(('bl', 'blx'))
    offtableop = set(('tbb', 'tbh'))
    f = open('instrs.info', 'w')
    curr_off = 0

    # Linearly disassemble
    while curr_off < textsec.size:
        for e in dis.disasm_lite(textraw[curr_off:], textsec.addr + curr_off):
            curr_off += e[1]
            if e[2].split('.')[0] == 'cmp': last_cmp = tuple(e[3].split(','))
            instr = ('%x' % e[0]).rjust(8) + ':\t' + e[2].ljust(7) + ' ' + e[3].replace(', ', ',').replace(' ', '|')
            m = pcrelre.search(instr)
            if m:
                # Insert label for PC relative loads
                dest = (e[0] & 0xFFFFFFFC) + int(m.group(1), 16) + 4
                if dest < curr_off + textsec.addr: negpcrel = True
                inlinedata[dest] = load_size(e[2], e[3])
                instr = pcrelre.sub('0x%X' % dest, instr)
            elif e[2] in calls and e[3].startswith('#'):
                # Insert plt symbol
                instr += plts.get(int(e[3][1:], 16), '')
            elif e[2].startswith('adr'):
                # Insert label for PC relative add
                const = e[3].split(', ')[1]
                last_adr_dest = (e[0] & 0xFFFFFFFC) + int(const[1:], 16) + 4
                last_adr_reg = e[3].split(',')[0]
                instr = instr.replace(const, '0x%x' % last_adr_dest)
            elif e[2].startswith('addw'):
                # PC relative double loads load address with addw
                m = pcreladdre.search(e[3])
                if m:
                    dest = (e[0] & 0xFFFFFFFC) + int(m.group(2), 16) + 4
                    inlinedata[dest] = 8
                    instr = ('%x' % e[0]).rjust(8) + ':\tadr    ' + m.group(1) + (',0x%X' % dest)
            f.write(instr + '\n')
            if e[2] in offtableop or e[2].startswith('ldr'):
                m = pcreltblre.search(e[3])
                if m:
                    # Process inline jumptable
                    offsize, tablesize = eval_tb_size(e[2], last_cmp, m.group(1) if m.group(1) is not None else m.group(3))
                    if offsize > 2:
                        # ldr jumptable
                        last_adr_reg = None
                        for i in xrange(0, tablesize, 4): inlinedata[last_adr_dest + i] = 4
                    else:
                        # tb jumptable
                        tb_process(offsize, curr_off + textsec.addr, textraw[curr_off:curr_off + tablesize], f)
                        curr_off += tablesize
                        break
                else:
                    # adr + ldr
                    m = baseregre.search(e[3])
                    if m and last_adr_reg == m.group(1):
                        inlinedata[last_adr_dest] = load_size(e[2], e[3])
                        last_adr_reg = None
            if curr_off + textsec.addr in inlinedata: break
        else:
            if curr_off < textsec.size: inlinedata[curr_off + textsec.addr] = 2
        while curr_off + textsec.addr in inlinedata:
            # Parse inline data
            pc = curr_off + textsec.addr
            size = inlinedata.pop(pc)
            if size == 1:
                vals = unpack('<BB', textraw[curr_off:curr_off+2])
                f.write(('%x' % pc).rjust(8) + ':\t.byte   0x%x\n' % vals[0])
                f.write(('%x' % (pc+1)).rjust(8) + ':\t.byte   0x%x\n' % vals[1])
                size = 2
            else:
                if size == 8:
                    inlinedata[pc+4] = 4
                    size = 4
                val = unpack('<H' if size == 2 else '<I', textraw[curr_off:curr_off+size])[0]
                f.write(('%x' % pc).rjust(8) + ':\t' + ('.short' if size == 2 else '.word').ljust(7) + ' 0x%x\n' % val)
            curr_off += size

        if secondpass and curr_off >= textsec.size and negpcrel:
            # If some PC relative load with negative offsets are found, a second pass is necessary
            secondpass = False
            curr_off = 0
            last_cmp = ('', '')
            last_adr_dest = 0
            last_adr_reg = None
            f.close()
            f = open('instrs.info', 'w')

    f.close()
