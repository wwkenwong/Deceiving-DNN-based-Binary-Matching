"""
Process PC relative addressing
"""

import re
from subprocess import check_output
from utils.ail_utils import ELF_utils

def info_collect(f):
    """
    Retrieve info about .got.plt section
    :param f: path to target executable
    """
    info = check_output("readelf -S " + f + " | awk '$2==\".got.plt\" {print $2,$4,$5,$6}'", shell=True).strip()
    with open('gotplt.info', 'w') as f: f.write(info)
    def mapper(l):
        items = l.split()
        # name ;  begin addr; ... ; size
        return (items[0], (int(items[1], 16), int(items[3], 16)))
    return dict(map(mapper, info.split('\n')))

def thunk_identify(ls):
    """
    Find x86 32bit thunk routines retriving program counter
    :param ls: assembler lines
    :return: list of virtual addresses
    """
    res = set()
    thunkre = re.compile('\(\%esp\)\,\%e(ax|bx|cx|bp|si|di)', re.I)

    for i in xrange(len(ls)):
        l = ls[i]
        if thunkre.search(l) and "mov" in l:
            t = ls[i+1]
            if "ret" in t.split()[-1]:
                res.add(l.split(":")[0].strip())
    if len(res) == 0: print "PIC position location can not be found!!"
    with open('pic_thunk.info', 'w') as f:
        for e in res: f.write(e + '\n')
    return tuple(res)

def text_process_strip(f):
    """
    Find thunk PC invocations and substitute .got.plt offsets with _GLOBAL_OFFSET_TABLE_ symbol
    :param f: path to target executable
    """
    sec_symb = {'.got.plt': '$_GLOBAL_OFFSET_TABLE_'}
    pic_map = info_collect(f)
    with open(f + '.temp') as fd:
        ls = fd.readlines()
    pc_thunk_addr = thunk_identify(ls)

    for i in xrange(1,len(ls)):
        l = ls[i]
        if "call" in l and next((addr for addr in pc_thunk_addr if addr in l), None):
            t = ls[i+1]
            items = t.split('\t')
            addr_s = items[0].strip().rstrip(':')
            items = items[2].split()
            if len(items) != 2 or items[0] != "add": continue
            # typically, it should look like this
            # 804c466: add    $0x2b8e,%ebx
            off_s = items[-1].split(',')[0][1:]
            try: off = int(off_s, 16)
            except: continue
            addr = int(addr_s, 16)
            baddr = addr + off
            for key, value in pic_map.iteritems():
                if value[0] == baddr:
                    ls[i+1] = t.replace('$'+off_s, sec_symb[key])
                elif value[0] < baddr < value[0] + value[1]:
                    print "Unhandled PIC situation at 0x" + addr_s

    with open(f + '.temp', 'w') as fd:
        fd.writelines(ls)


def picprocess32(filepath):
    """
    PC relative operation in x86 32 bit code such as:
     call   804c452 <__x86.get_pc_thunk.bx>
     add    $0x2b8e,%ebx
     mov    $0x10, (%ebx)
    This operation usually loads into %ebx the address of the _GLOBAL_OFFSET_TABLE_
    Further adjustments are operated in the analysis phase
    :param filepath: path to target executable
    """
    if ELF_utils.elf_32() and ELF_utils.elf_exe() and not ELF_utils.elf_arm():
        text_process_strip(filepath)


def picprocess64(filepath):
    """
    PC relative operations in x86 64 bit code
    typical instruction disassembled by objdump like this
        4005c9:    48 8b 05 58 08 20 00     mov    0x200858(%rip),%rax        # 600e28 <__libc_start_main@plt+0x200a28>
    should be rewritten in this format
        4005c9:   ...................     mov    S_0x600e28(%rip), %rax
    :param filepath: path to target executable
    """
    if not ELF_utils.elf_64(): return

    with open(filepath + '.temp') as f:
        lines = f.readlines()

    pat = re.compile(r'0x[0-9a-f]+\(%rip\)')

    for i in xrange(len(lines)):
        l = lines[i]
        if "#" in l:
            m = pat.search(l)
            if m:
                items = l.split('#')
                des = items[1].split()[0]
                sub = m.group(0)
                sub1 = "0x" + des + "(%rip)"
                l = items[0]
                l = l.replace(sub, sub1)
                lines[i] = l + "\n"

    with open(filepath + '.temp', 'w') as f:
        f.writelines(lines)
