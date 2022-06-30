"""
Discover main function address
"""

import os
import config
from utils.ail_utils import ELF_utils


def main_discover(filename):
    """
    Find main function address and store it to file
    :param filename: path to target executable
    """
    os.system('file ' + filename + ' > elf.info')
    if ELF_utils.elf_exe():

        os.system(config.objdump + ' -Dr -j .text '+ filename + ' > ' + filename + '.temp')

        with open(filename + '.temp') as f:
            lines = f.readlines()

        ll = len(lines)
        main_symbol = ""

        if config.arch == config.ARCH_X86:
            for i in xrange(ll):
                l = lines[i]
                # when not using O2 to compile the original binary, we will remove all the _start code,
                # including the routine attached on the original program. In that case, we can not discover the
                # main function
                if "<__libc_start_main@plt>" in l:
                    main_symbol = lines[i-1].split()[-1] if ELF_utils.elf_32() \
                        else lines[i-1].split()[-1].split(',')[0]
                    if main_symbol == '%eax':
                        # to fit gcc-4.8 -m32, the address is mov to %eax, then push to stack
                        main_symbol = lines[i - 2].split()[-1].split(',')[0].split('0x')[1]
                    else:
                        main_symbol = main_symbol.split('0x')[1]
                    break
                #lines[i-1] = lines[i-1].replace(main_symbol, "main")
                #main_symbol = main_symbol[1:].strip()
                #print main_symbol

            ## Some of the PIC code/module rely on typical pattern to locate
            ## such as:

            ##	804c460: push   %ebx
            ##	804c461: call   804c452 <__i686.get_pc_thunk.bx>
            ##	804c466: add    $0x2b8e,%ebx
            ##	804c46c: sub    $0x18,%esp

            ## What we can do this pattern match `<__i686.get_pc_thunk.bx>` and calculate
            ## the address by plusing 0x2b8e and  0x804c466, which equals to the begin address of GOT.PLT table

            ## symbols can be leveraged in re-assemble are
            ##	_GLOBAL_OFFSET_TABLE_   ==    ** .got.plt **
            ##	....
        elif config.arch == config.ARCH_ARMT:
            ## 1035c:       4803            ldr     r0, [pc, #12]   ; (1036c <_start+0x28>)
            ## 1035e:       4b04            ldr     r3, [pc, #16]   ; (10370 <_start+0x2c>)
            ## 10360:       f7ff efde       blx     10320 <__libc_start_main@plt>
            ## 10364:       f7ff efe8       blx     10338 <abort@plt>
            ## ...
            ## 1036c:       0001052d
            for i in xrange(ll):
                l = lines[i]
                if '<__libc_start_main@plt>' in l:
                    j = i - 1
                    while j > 0:
                        if 'ldr' in lines[j] and 'r0' in lines[j]:
                            pcraddr = lines[j].split(';')[1].strip().split()[0][1:]
                            break
                        j -= 1
                    j = i + 1
                    while j < ll:
                        if lines[j].strip().startswith(pcraddr):
                            main_symbol = lines[j].split()[1]
                            if len(main_symbol) < 8: main_symbol = lines[j+1].split()[1] + main_symbol
                            main_symbol = int(main_symbol.lstrip('0'), 16) & (-2)
                            main_symbol = '%X' % main_symbol
                            break
                        j += 1
                    break
        else:
            raise Exception('Unknown arch')


        with open("main.info", 'w') as f:
            f.write('S_0x' + main_symbol.upper() + '\n')
