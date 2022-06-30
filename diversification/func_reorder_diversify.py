from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *
from junkcodes import get_junk_codes


class func_reorder_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.funcs = funcs

    def update_preceding_func(self, pre, f):
        pre_f_instrs = self.func_instrs(pre)
        last_loc = self._get_loc(pre_f_instrs[-1])
        last_loc.loc_label = ''

        junk = get_junk_codes(last_loc, 0)
        for j in junk:
            self.append_instrs(j, last_loc)
        i = DoubleInstr((self._ops['jmp'], Label(f.func_name), last_loc, None))
        self.append_instrs(i, last_loc)

    def update_succeeding_func(self, f, suc):
        f_instrs = self.func_instrs(f)
        last_loc = self._get_loc(f_instrs[-1])
        last_loc.loc_label = ''

        junk = get_junk_codes(last_loc, 0)
        for j in junk:
            self.append_instrs(j, last_loc)
        i = DoubleInstr((self._ops['jmp'], Label(suc.func_name), last_loc, None))
        self.append_instrs(i, last_loc)

    def update_current_func(self, f1, f1_last_addr, f2):
        f1_instrs = self.func_instrs(f1)
        f2_instrs = self.func_instrs(f2)
        last_loc = Loc(label='', addr=f1_last_addr, visible=True)
        if len(f1_instrs) > len(f2_instrs):
            for idx in range(len(f1_instrs)):
                if len(f2_instrs) <= idx:
                    floc = self._get_loc(f1_instrs[idx])
                    floc.loc_label = ''
                    i = SingleInstr((self._ops['nop'], floc, False))
                    self.replace_instrs(i, floc, f1_instrs[idx])
                elif idx < len(f2_instrs):
                    # Note: the get_loc return the reference of loc, which may cause side effect
                    floc = self._get_loc(f1_instrs[idx])
                    sloc = self._get_loc(f2_instrs[idx])
                    floc.loc_label = sloc.loc_label
                    sh_ = set_loc(f2_instrs[idx], floc)
                    self.replace_instrs(sh_, floc, f1_instrs[idx])
        else:
            for idx in range(len(f2_instrs)):
                if idx >= len(f1_instrs):
                    sloc = self._get_loc(f2_instrs[idx])
                    loc = Loc(label=sloc.loc_label, addr=f1_last_addr, visible=True)
                    sh_ = set_loc(f2_instrs[idx], loc)
                    self.insert_instrs(sh_, last_loc)
                elif idx == len(f1_instrs) - 1:
                    loc = self._get_loc(f1_instrs[idx])
                    sloc = self._get_loc(f2_instrs[idx])
                    loc.loc_label = sloc.loc_label
                    sh_ = set_loc(f2_instrs[idx], loc)
                    self.replace_instrs(sh_, loc, f1_instrs[idx])
                else:
                    floc = self._get_loc(f1_instrs[idx])
                    sloc = self._get_loc(f2_instrs[idx])
                    floc.loc_label = sloc.loc_label
                    sh_ = set_loc(f2_instrs[idx], floc)
                    self.replace_instrs(sh_, floc, f1_instrs[idx])

    def reorder_funcs(self, f1_idx, f2_idx):
        f1_pre = self.funcs[f1_idx - 1]
        f1 = self.funcs[f1_idx]
        f1_suc = self.funcs[f1_idx + 1]

        f2_pre = self.funcs[f2_idx - 1]
        f2 = self.funcs[f2_idx]
        f2_suc = self.funcs[f2_idx + 1]

        # print 'doing function reordering %s <-> %s' % (f1.func_name, f2.func_name)

        self.update_preceding_func(f1_pre, f1)
        self.update_preceding_func(f2_pre, f2)

        self.update_succeeding_func(f1, f1_suc)
        self.update_succeeding_func(f2, f2_suc)

        self.update_process()

        # self.print_func(f1)
        # self.print_func(f1_suc)
        # self.print_func(f2)
        # self.print_func(f2_suc)

        self.update_current_func(f1, f1_suc.func_begin_addr, f2)
        self.update_current_func(f2, f2_suc.func_begin_addr, f1)
        self.update_process()

    def func_div_process(self):
        print 'function reorder diversifying...'
        f1_i, f2_i = self.get_2_diff_randint(0, len(self.funcs) - 4)
        if len(self.funcs) < 15:
            print 'the amount of functions is not enough to be reordered'
            return
        while self.is_main(f1_i) or self.is_main(f1_i + 1) or self.is_main(f1_i + 2) or \
                self.is_main(f2_i) or self.is_main(f2_i + 1) or self.is_main(f2_i + 2):
            f1_i, f2_i = self.get_2_diff_randint(0, len(self.funcs) - 4)
        self.reorder_funcs(f1_i + 1, f2_i + 1)

    def visit(self, instrs):
        self.instrs = copy.deepcopy(instrs)
        self.func_div_process()
        return self.instrs
