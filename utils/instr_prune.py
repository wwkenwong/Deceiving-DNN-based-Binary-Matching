"""
Remove useless code
Functions usually attached at the beginning of the .text sections:
- _start
- __do_global_dtors_aux
- frame_dummy
Functions usually attached at the end of the .text sections:
- __do_global_ctors_aux
- __libc_csu_init
- __libc_csu_fini
"""

import sys, os

fn = sys.argv[1]
c = sys.argv[2]
# in the first round, we get the binary in test folder while
# the next N-1 rounds we get the binary in the current folder

def dump_sections(fn):
    path = ('./test/' + fn) if c == 1 else ('./' + fn)
    os.system('readelf -S '+path+' > sec1.info')
    with open('sec1.info') as f:
        lines = f.readlines()
    ctors = 0
    jcr = 0
    for l in lines:
        if '.jcr' in l:
            jcr = int(l.split()[3], 16)
            jcr = hex(jcr)[2:]
            jcr = '0x'+jcr.upper()
        elif '.ctors' in l:
            ctors = int(l.split()[3], 16)
            ctors = hex(ctors)[2:]
            ctors = '0x'+ctors.upper()
    return ctors, jcr

ctors, jcr = dump_sections(fn)

# print '6: optimization --> reduce text segment size'

with open('final.s') as f:
    lines = f.readlines()

lines.reverse()

s1, e1, s2, e2 = 0, 0, 0, 0

found_sec_pattern = False
found_first_pattern = False
detect_sec_pattern = True
detect_first_pattern = True

for i in range(len(lines)):
    l = lines[i]
    if found_sec_pattern == False and detect_sec_pattern == True and ctors in l:
        # we are in the second zone
        s2 = i - 14
        found_sec_pattern = True
    elif found_sec_pattern == True and detect_sec_pattern == True and '_GLOBAL_OFFSET_TABLE_' in l:
        # sometimes we just can not find nop above the matched function, let's just give it
        detect_sec_pattern = False
        s2 = 0
    elif found_sec_pattern == True and detect_sec_pattern == True and 'nop' in l:
        e2 = i
        detect_sec_pattern = False
        print "     identify function __do_global_ctors_aux"
    elif found_first_pattern == False and detect_first_pattern == True and jcr in l:
        s1 = i - 5
        found_first_pattern = True
    elif '__libc_start_main' in l and detect_first_pattern == True:
        detect_first_pattern = False
        e1 = i + 12
        print "     identify function _start; __do_global_dtors_aux; frame_dummy"


if s1 != 0 and e1 != 0:
    for i in range(s1, e1+1):
        lines[i] = ""

if s2 != 0 and e2 != 0:
    for i in range(s2, e2+1):
        lines[i] = ""

print "   remove these useless functions"

lines.reverse()

with open('final.s', 'w') as f:
    f.writelines(lines)