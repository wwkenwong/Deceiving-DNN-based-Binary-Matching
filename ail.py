"""
Processing skeleton
"""

from termcolor import colored

from analysis.analysis_process import Analysis
# diversifications
from diversification.bb_opaque_diversify import *
from diversification.bb_reorder_diversify import *
from diversification.func_inline_diversify import *
from diversification.bb_branchfunc_diversify import *
from diversification.bb_split_diversify import *
from diversification.func_reorder_diversify import *
from diversification.bb_flatten_diversify import *
from diversification.bb_merge_diversify import *
from diversification.instr_garbage_diversify import *
from diversification.instr_replace_diversify import *
from diversification.bb_opaque_diversify_gen2 import *

from disasm import pre_process
from disasm.disassemble_process import Disam
from postprocess import post_process, post_process_lib, post_process_data


class Ail(object):
    """
    Processing skeleton
    """

    def __init__(self, filepath):
        """
        :param filepath: path to executable
        """
        self.file = filepath
        self.funcs = []
        self.secs = []
        self.instrs = []
        self.g_bss = []

    def sections(self):
        """
        Load section info
        """
        def sec_mapper(line):
            items = line.split()
            return Section(items[0], int(items[1], 16), int(items[3], 16))
        with open('sections.info') as f:
            self.secs += map(sec_mapper,f)

    def externfuncs(self):
        """
        Load library functions
        """
        def func_mapper(line):
            items = line.split()
            return Func(items[1], int(items[0], 16), 0, True)
        with open('externfuncs.info') as f:
            self.funcs += map(func_mapper, f)

    def userfuncs(self):
        """
        Load function symbols
        """
        def func_mapper(line):
            items = line.split()
            return Func(items[1][1:-2].split('@')[0], int(items[0], 16), 0, False)
        with open('userfuncs.info') as f:
            self.funcs += map(func_mapper,
                filter(lambda line: not ('-0x' in line or '+0x' in line), f))

    def get_userfuncs(self):
        """
        Get functions
        """
        return filter(lambda f: not f.is_lib, self.funcs)

    def global_bss(self):
        """
        Load global bss symbols
        """
        def bss_mapper(line):
            items = line.split()
            return (items[0][1:].upper(), items[1].strip())
        with open('globalbss.info') as f:
            self.g_bss += map(bss_mapper, f)

    def ehframe_dump(self):
        """
        Write eh_frame to file
        """
        with open('eh_frame.data') as eh:
            with open('final.s', 'a') as f:
                f.write(eh.read())

    def post_process(self, instrument=False):
        """
        Post processing
        :param instrument: True to apply instrumentations
        """
        post_process.main(instrument)
        post_process_data.main()
        post_process_lib.main()

    def pre_process(self):
        """
        Pre processing
        """
        pre_process.main()

    def instrProcess(self, instrument=False, docfg=False,specific_function=None):
        """
        Process instructions
        :param instrument: True to apply instrumentations
        :param docfg: True to evaluate control flow graph
        """
        self.pre_process()
        il, fl, re = Disam.disassemble(self.file, self.funcs, self.secs)

        print colored('3: ANALYSIS', 'green')
        fbl, bbl, cfg_t, cg, il, re = Analysis.analyze(il, fl, re, docfg)  # @UnusedVariable

        ####################################################
        u_funcs = filter(lambda f: f.is_lib is False, fl)
        il_ = il
        if specific_function != None :
            arr = []
            # [function_name,addr_tmp]
            for specific in specific_function:
                for xxx in u_funcs:
                    chk = str(xxx)
                    if chk.startswith(specific[0]+"@") or chk.startswith(specific[1]+"@"):
                        arr.append(xxx)
            if len(arr)!=0:
                u_funcs = list(set(arr))
            else:
                # right now, we will crash directly if the symbol isn't exist 
                raise Exception('Fail') 

        #print(u_funcs)
        # u_funcs = [S_0x80499A6@0x80499A6-0x8049BEF] OR [set_suffix_length@0x804985D-0x8049A4A]
        fbl_tmp = {}
        for fun_label_tmp in u_funcs:
            #try:
                fl__tmp = str(fun_label_tmp) 
                fl__tmp = fl__tmp.split("@")[-1]
                # This is for the case if we still have symbol 
                fl_backup = str(fun_label_tmp).split("@")[0]
                fl__tmp = str(fl__tmp.split("-")[0])
                query_fl = "S_"+fl__tmp
                if query_fl in fbl.keys():
                    fbl_tmp[query_fl] = fbl[query_fl] 
                elif fl_backup in fbl.keys():
                    fbl_tmp[fl_backup] = fbl[fl_backup]
            # except:
            #     pass 
        
        if len(fbl_tmp)>0:
            fbl = fbl_tmp

        diversify_class = config.diver_classes[config.diversification_mode]
        if diversify_class is not None:
            div = diversify_class(funcs=u_funcs, fb_tbl=fbl, cfg_tbl=cfg_t)
            il_ = div.visit(il_)

        if instrument:
            print colored('4: INSTRUMENTATION', 'green')
            for worker in config.instrumentors:
                il = worker['main'].perform(il, fl)

        print colored(('5' if instrument else '4') + ': POST-PROCESSING', 'green')
        Analysis.post_analyze(il_, re)
        self.post_process(instrument)
