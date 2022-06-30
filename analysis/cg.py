import sys
from disasm import Types
from visit import ailVisitor
from utils.ail_utils import dec_hex, Opcode_utils


class cg(ailVisitor):
    """
    A Call Graph construction impelmentation.
    Constructs simple CG based on direct control flow transfer (call/jump)
    """

    def __init__(self):
        self.cg_tbl = {}
        self.cfi_tbl = {}

    def update_cgtbl(self, l, func):
        ll = self.cg_tbl.get(l.loc_addr, [])
        ll.insert(0, func)
        self.cg_tbl[l.loc_addr] = ll

    def update_cfitbl(self, func, l):
        ll = self.cfi_tbl.get(func.func_name, [])
        ll.insert(0, l)
        self.cfi_tbl[func.func_name] = ll

    def func_info(self, l):
        for h in self.funcs:
            if h.func_begin_addr <= l.loc_addr < h.func_end_addr:
                return h
        raise Exception(dec_hex(l.loc_addr) + ': cannot find corresponding function')

    def cg_process(self, e, l):
        if isinstance(e, Types.JumpDes):
            f = self.func_info(l)
            if not (f.func_begin_addr <= e < f.func_end_addr):
                self.update_cgtbl(l, f)
        elif isinstance(e, Types.CallDes):
            if not e.is_lib: self.update_cgtbl(l, e)

    def vinst_tail(self, instrs):
        for h in instrs:
            if isinstance(h, Types.DoubleInstr):
                p, e, l, _ = h
                if Opcode_utils.is_cp(p) and isinstance(e, (Types.JumpDes, Types.CallDes)):
                    self.cg_process(e, l)
        return instrs

    def visit(self, instrs):
        return self.vinst_tail(instrs)

    def cfi_specified_tbl(self):
        for k,v in self.cg_tbl.iteritems():
            for f in v:
                self.update_cfitbl(f, k)

    def print_cg_graph(self):
        for k,v in self.cfi_tbl.iteritems():
            sys.stdout.write(dec_hex(k))
            for f in v:
                print '    ' + f.func_name

    def print_cfi_specified_graph(self):
        self.cfi_specified_tbl()
        for k,v in self.cfi_tbl.iteritems():
            print k
            for l in v:
                print '    ' + dec_hex(l)

    def get_cg_table(self):
        return self.cg_tbl

    def get_cfi_tbl(self):
        self.cfi_specified_tbl()
        return self.cfi_tbl
