"""
Workfiles initialization
"""

import os
import sys

from termcolor import colored

import ail
import config
from disasm import pic_process, extern_symbol_process, arm_process
from utils.ail_utils import ELF_utils


class Init(object):
    """
    Processing initializer
    """

    def __init__(self, filepath):
        """
        :param filepath: path to executable
        """
        self.file = filepath

    def disassemble(self):
        """
        Dump .text, .rodata, .data, .eh_frame, .got to file
        """
        print colored('1: DISASSEMBLE', 'green')
        ret = os.system(config.objdump + ' -Dr -j .text ' + self.file + ' > ' + self.file + '.temp')
        self.checkret(ret, self.file + '.temp')

        if not ELF_utils.elf_arm():
            if ELF_utils.elf_32():
                pic_process.picprocess32(self.file)
            else:
                extern_symbol_process.globalvar(self.file)
                pic_process.picprocess64(self.file)

        ret = os.system(config.objdump + " -s -j .rodata " + self.file + " | grep \"^ \" | cut -d \" \" -f3,4,5,6 > rodata.info")
        self.checkret(ret, 'rodata.info')
        ret = os.system(config.objdump + " -s -j .data " + self.file + " | grep \"^ \" | cut -d \" \" -f3,4,5,6 > data.info")
        self.checkret(ret, 'data.info')
        os.system(config.objdump + " -s -j .eh_frame " + self.file + " | grep \"^ \" | cut -d \" \" -f3,4,5,6 > eh_frame.info")
        if not ELF_utils.elf_arm(): os.system(config.objdump + " -s -j .eh_frame_hdr " + self.file + " | grep \"^ \" | cut -d \" \" -f3,4,5,6 > eh_frame_hdr.info")
        os.system(config.objdump + " -s -j .got " + self.file + " | grep \"^ \" | cut -d \" \" -f3,4,5,6 > got.info")

    def process(self):
        """
        Process sections
        """
        self.pltProcess()
        self.textProcess()
        self.sectionProcess()
        self.bssHandler()
        self.export_tbl_dump()
        self.userFuncProcess()

    def bssHandler(self):
        """
        Generate .bss dump and extract global bss symbols
        """
        with open("sections.info") as f:
            bssinfo = next((l for l in f if '.bss' in l), None)
            size = int(bssinfo.split()[3], 16) if bssinfo is not None else 0
        with open("bss.info", 'w') as f:
            f.write(".byte 0x00\n" * size)
        os.system('readelf -sW ' + self.file + ' | grep OBJECT | awk \'/GLOBAL/ {print $2,$8}\' > globalbss.info')
        os.system('readelf -rW ' + self.file + ' | grep _GLOB_DAT | grep -v __gmon_start__ | awk \'{print $1,$5}\' > gotglobals.info')

    def textProcess(self):
        """
        Code disassembly dump
        """
        # useless_func_del.main(self.file)
        if ELF_utils.elf_arm(): arm_process.arm_process(self.file)
        else:
            extern_symbol_process.pltgot(self.file)
            os.system("cat " + self.file + ".temp | grep \"^ \" | cut -f1,3 > instrs.info")
        os.system("cut -f 1 instrs.info > text_mem.info")

    def userFuncProcess(self):
        """
        Dump function symbols
        """
        os.system("cat " + self.file + ".temp | grep \"<\" | grep \">:\" > userfuncs.info")
        os.system("cat fl | grep -v \"<S_0x\" >> userfuncs.info")

    def sectionProcess(self):
        """
        Dump section boundaries
        """
        badsec = '.got.plt' if ELF_utils.elf_32() else'.data.rel.ro'
        os.system("readelf -SW " + self.file + " | awk \'/data|bss|got/ {print $2,$4,$5,$6} \' | awk \ '$1 != \"" + badsec + "\" {print $1,$2,$3,$4}\' > sections.info")
        os.system("readelf -SW " + self.file + " | awk \'/text/ {print $2,$4,$5,$6} \' > text_sec.info")
        os.system("readelf -SW " + self.file + " | awk \'/init/ {print $2,$4,$5,$6} \' | awk \'$1 != \".init_array\" {print $1,$2,$3,$4}\' > init_sec.info")
        if os.path.isfile('init_array.info'): os.remove('init_array.info')
        os.system(config.objdump + " -s -j .init_array " + self.file + " >> init_array.info 2>&1")
        os.system("readelf -SW " + self.file + " | awk '$2==\".plt\" {print $2,$4,$5,$6}' > plt_sec.info")

    def export_tbl_dump(self):
        """
        Dump global symbols
        """
        os.system("readelf -s " + self.file + " | grep GLOBAL > export_tbl.info")

    def pltProcess(self):
        """
        Dump plt section
        """
        os.system(config.objdump + " -j .plt -Dr " + self.file + " | grep \">:\" > plts.info")

    def ailProcess(self, instrument=False,specific_function=None):
        """
        Invoke processing skeleton
        :param instrument: True to apply instrumentations
        """
        processor = ail.Ail(self.file)
        processor.sections()
        processor.userfuncs()
        processor.global_bss()
        # try to construct control flow graph and call graph
        # which can help to obfuscating process
        processor.instrProcess(instrument, docfg=True,specific_function=specific_function)

    def checkret(self, ret, path):
        """
        Check return of dump operation
        :param ret: shell return code
        :param path: dump file path
        """
        if ret != 0 and os.path.isfile(path):
            os.remove(path)


def main(filepath, instrument=False,specific_function=None):
    """
    Init processing
    :param filepath: path to executable
    :param instrument: True to apply instrumentation
    """
    if ELF_utils.elf_strip() and ELF_utils.elf_exe():
        init = Init(filepath)
        init.disassemble()
        init.process()
        init.ailProcess(instrument,specific_function=specific_function)
    else:
        sys.stderr.write('Error: binary is not stripped or is a shared library\n')
