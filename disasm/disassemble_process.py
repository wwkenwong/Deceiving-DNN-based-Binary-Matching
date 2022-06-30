import os
import config
import filter_nop
import useless_func_del
from termcolor import colored
from ail_parser import AilParser
from analysis.reassemble_symbol_get import reassemble
from analysis.disassemble_validator import dis_validator
from utils.ail_utils import Time_Record as TR, read_file


class Disam(object):
    """
    Disassembly recovery skeleton
    """

    @staticmethod
    def disasm_skip(filepath, ba, ea):
        os.system(config.objdump + " -Dr -j .text " + filepath + " --start-address=" + str(ba) + " --stop-address=" + str(ea) + " > " + filepath + ".temp")
        useless_func_del.main(filepath)
        os.system("cat " + filepath + ".disassemble | grep \"^ \" | cut -f1,3 > instrs.info")
        filter_nop.main()
        os.system("cut -f 1 instrs.info > text_mem.info")

    @staticmethod
    def get_userfuncs(funcs):
        """
        Filter out library functions
        :param funcs: list of functions
        """
        return filter(lambda f: not f.is_lib, funcs)

    @staticmethod
    def disassemble(filepath, funcs, secs):
        """
        Read disassemble dump, parse instrctions and reconstruct symbolic information
        :param filepath: path to target executable
        :param funcs: list of functions
        :param secs: list of sections
        :return: instruction list, updated function list, symbol reconstruction object
        """
        ailpar = AilParser()
        re = reassemble()
        dis_valid = dis_validator()
        il = []
        fl = []
        total = 0.0
        cond = False
        while not cond and total < 600.0:
            once = TR.get_utime()
            ailpar.set_funcs(funcs)
            ailpar.set_secs(secs)
            ailpar.processInstrs(read_file('instrs.info'))
            fl = ailpar.get_funcs()

            il = re.visit_heuristic_analysis(ailpar.get_instrs())
            il = re.lib32_processing(il, fl)
            il = re.add_func_label(Disam.get_userfuncs(fl), il)

            print colored('2: DISASSEMBLY VALIDATION', 'green')
            dis_valid.visit(il)
            adjust_list = dis_valid.trim_results()
            if len(adjust_list) != 0:
                print '     disassembly error found!'
                if config.arch == config.ARCH_ARMT: exit('Not implemented')
                Disam.disasm_skip(filepath, adjust_list[0][0], adjust_list[0][1])
                total += TR.elapsed(once)
            else:
                cond = True

        return (il, fl, re)
