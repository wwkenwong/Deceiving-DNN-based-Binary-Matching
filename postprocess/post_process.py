"""
Code post processing
"""

import os

import config
import inline_update
from utils.ail_utils import ELF_utils


def main(instrument=False):
    """
    Transform malformed code and add main symbol
    :param instrument: True to insert instrumentation code
    """

    with open("final.s") as f:
        lines = f.readlines()

    if ELF_utils.elf_exe():
        main_symbol1 = ''

        with open('main.info') as f:
            main_symbol1 = f.readline().strip()

        if main_symbol1 != '':
            def helpf(l):
                if '__gmon_start__' in l:
                    l = ''
                elif 'lea 0x7FFFFFFC(,%ebx,0x4),%edi' in l:
                    l = l.replace('0x7FFFFFFC', '0x7FFFFFFFFFFFFFFC')
                elif 'movzbl $S_' in l:
                    l = l.replace('movzbl $S_', 'movzbl S_')
                elif 'jmpq ' in l and '*' not in l:
                    l = l.replace('jmpq ', 'jmp ')
                elif 'repz retq' in l:
                    # to solve the error of 'expecting string instruction after `repz'
                    l = l.replace('repz retq', 'retq')
                elif 'repz ret' in l:
                    l = l.replace('repz ret', 'ret')
                elif 'nop' in l:
                    l = l.replace('nop', ' ')
                if main_symbol1 + ' :' in l:
                    rep = '.globl main\nmain : '
                    if instrument:
                        rep += '\n'.join(map(lambda e: e['plain'].beforemain, config.instrumentors)) + '\n'
                    l = l.replace(main_symbol1 + ' : ', rep)
                elif main_symbol1 in l:
                    l = l.replace(main_symbol1, 'main')
                return l
            lines = map(helpf, lines)

    with open("final.s", 'w') as f:
        f.writelines(lines)
        if instrument: f.write('\n'.join(map(lambda e: e['plain'].aftercode, config.instrumentors)) + '\n')

    if os.path.isfile('inline_symbols.txt'):
        inline_update.main()
