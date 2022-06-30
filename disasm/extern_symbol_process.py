"""
Process external symbols from shared libraries
"""

import re
import os
import config
from subprocess import check_output


def globalvar(filepath):
    """
    This code aims at solving glibc global variables issue some of the code contains comments like this:
        401599:       48 8b 3d 70 6c 20 00    mov    0x206c70(%rip),%rdi        # 608210 <stdout>
    instructions like this should be translated into:
        mov stdout,%rdi
    :param filepath: path to target executable
    """

    with open(filepath + '.temp') as f:
        lines = f.readlines()

    pat_d = re.compile(r'0x[0-9a-f]+\(%rip\)')
    pat_s = re.compile(r'<([^@]+)(@@(?!Base).*)?>')

    for i in range(len(lines)):
        l = lines[i]
        if "#" in l and not "+" in l:
            m_s = pat_s.search(l)
            m_d = pat_d.search(l)
            if m_s and m_d:
                src = m_s.group(1)
                des = m_d.group(0)
                l = l.split('#')[0]
                l = l.replace(des, src)
                lines[i] = l + '\n'

    with open(filepath + '.temp', 'w') as f:
        f.writelines(lines)


def pltgot(filepath):
    """
    Handle library functions linked through .plt.got and substitute them with correct symbols
    :param filepath: path to target executable
    """
    with open('plts.info') as f:
        f.seek(-2, os.SEEK_END)
        while f.read(1) != '\n': f.seek(-2, os.SEEK_CUR)
        lastplt = f.readline().split()
    lastplt = (int(lastplt[0],16), re.escape(lastplt[1].rstrip('>:')))

    pltgotsym = check_output('readelf -r ' + filepath + ' | awk \'/_GLOB_DAT/ {print $1,$5}\' | grep -v __gmon_start__ | cat', shell=True).strip()
    if len(pltgotsym) == 0: return
    def pltsymmapper(l):
        items = l.strip().split()
        return (int(items[0], 16), items[1].split('@')[0])
    pltgotsym = dict(map(pltsymmapper, pltgotsym.split('\n')))

    pltgottargets = check_output(config.objdump + ' -Dr -j .plt.got ' + filepath + ' | grep jmp | cut -f1,3', shell=True)
    def pltgotmapper(l):
        items = l.strip().split()
        dest = int(items[4] if '#' in items else items[2].lstrip('*'), 16)
        return (int(items[0].rstrip(':'), 16), dest)
    pltgottargets = dict(map(pltgotmapper, pltgottargets.strip().split('\n')))
    pltgottargets = {e[0]: '<' + pltgotsym[e[1]] + '@plt>' for e in pltgottargets.iteritems() if e[1] in pltgotsym}
    if len(pltgottargets) == 0: return

    pltgotre = re.compile(lastplt[1] + '\+(0x[0-9a-f]+)\>', re.I)
    def calldesmapper(l):
        m = pltgotre.search(l)
        if m:
            dest = lastplt[0] + int(m.group(1), 16)
            if dest in pltgottargets: return pltgotre.sub(pltgottargets[dest], l)
        return l
    with open(filepath + '.temp') as f:
        lines = map(calldesmapper, f)

    with open(filepath + '.temp', 'w') as f:
        f.writelines(lines)
