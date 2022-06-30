from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *

size_threshold = 500


class func_inline_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.fb_tbl = fb_tbl
        self.funcs = funcs
        self._collected_callers = []

    def target_func_scan(self):
        candidate_funcs = []

        for f_idx in range(len(self.funcs)):
            f = self.funcs[f_idx]
            size = f.func_end_addr - f.func_begin_addr
            if size < size_threshold and size != 13:  # why 13?
                tmp_callers = self.caller_collect(f.func_name)
                # if len(tmp_callers) >= 5:
                # the function being inlined should be called in adequate positions
                candidate_funcs.append((f_idx, f, tmp_callers))

        candidate_num = len(candidate_funcs)

        tf = None
        if candidate_num > 0:
            sample_limit = candidate_num * 2 + 1
            while sample_limit > 0 and len(self._collected_callers) == 0:
                sample_limit -= 1
                # random
                # f_idx, tf, callers = random.sample(candidate_funcs, 1)[0]

                # select the function with most callers
                candidate_funcs = sorted(candidate_funcs, key=lambda a: len(a[2]), reverse=True)
                f_idx, tf, callers = candidate_funcs[0]
                if self.is_main(f_idx):
                    # we do not inline main function
                    pass
                else:
                    self._collected_callers = callers
                    # if len(self._collected_callers) == 0:
                    #     print 'found zero caller function, skip'
        return tf

    def caller_collect(self, fn):
        """
        We simply change instructions like `call func_name`
        """
        def is_call(op):
            return Opcode_utils.is_call(op)

        callers = []
        for i in self.instrs:
            if isinstance(i, DoubleInstr):
                p, e, _, _ = i
                if is_call(p):
                    es = p_exp(e)
                    if es.find(fn) >= 0:
                        callers.append(i)
                        # print 'find caller at 0x%x: %s' % (get_loc(i).loc_addr, pp_print_instr(i))
        return callers

    def transform_caller(self, tf):
        # get the instructions of the target function
        tf_l = self.func_instrs(tf)
        def help(ci):
            _, e, l, _ = ci
            self.update_call(ci, e, copy.deepcopy(l), tf_l)

        map(help, self._collected_callers)
        self.symbol_dump(tf_l)

    def update_call(self, i, e, l, tf_l):
        def help(i, e, l):
            jmp_label = 'S_' + dec_hex(l.loc_addr) + '_next_inline'
            l1 = copy.deepcopy(l)
            l1.loc_label = jmp_label + ': '
            l3 = copy.deepcopy(l)
            l3.loc_label = ''
            l2 = copy.deepcopy(l)
            l2.loc_label = jmp_label + ': '
            i2 = DoubleInstr((self._ops['push'], Types.Label('$' + jmp_label), l, None))
            i3 = DoubleInstr((self._ops['jmp'], e, l3, None))
            i1 = SingleInstr((self._ops['nop'], l1, None))
            self.insert_instrs(i2, l)
            self.insert_instrs(i3, l)
            # inline instructions of the target function
            for _i in tf_l:
                if isinstance(_i, SingleInstr) and p_op(get_op(_i)) == 'ret':
                    ret_loc = get_loc(_i)
                    self.insert_instrs(DoubleInstr((self._ops['pop'], self._regs[2], ret_loc, None)), l)
                    ret_loc_no_label = copy.deepcopy(ret_loc)
                    ret_loc_no_label.loc_label = ''
                    self.insert_instrs(DoubleInstr((self._ops['jmp'], StarDes(self._regs[2]), ret_loc_no_label, None)), l)
                else:
                    self.insert_instrs(_i, l)
            self.replace_instrs(i1, l, i)

        if isinstance(e, Types.Symbol):
            if isinstance(e, Types.CallDes):
                if not e.is_lib:
                    help(i, e, l)
            else:
                help(i, e, l)
        elif isinstance(e, Types.Label):
            help(i, e, l)
        else:
            assert False, 'unsupported call'

    def symbol_collect(self, il):
        acc = []
        for i in il:
            l = get_loc(i)
            if l.loc_label.find(':') >= 0:
                acc.append(l.loc_label)
        return acc

    def symbol_dump(self, il):
        sl = self.symbol_collect(il)
        with open('inline_symbols.txt', 'w') as f:
            f.write('\n'.join(sl))

    def inline(self, tf, cl):
        tf_l = self.func_instrs(tf)

        def help(i):
            l = get_loc(i)
            map(lambda i: self.insert_instrs(i, l), tf_l)

        map(help, cl)
        self.symbol_dump(tf_l)
        self.update_process()

    def func_inline_process(self):
        tf = self.target_func_scan()
        if tf is None:
            print 'did not find candidate functions'
            return self.instrs
        else:
            if len(self._collected_callers) > 0:
                self.transform_caller(tf)
                self.update_process()
                # self.inline(tf, self._collected_callers)
                self._collected_callers = []
            else:
                print 'no caller is going to be inlined'
        return self.instrs

    def visit(self, instrs):
        self.instrs = copy.deepcopy(instrs)
        if len(self.funcs) >= 5:
            self.func_inline_process()
        else:
            print 'number of function is too small(%d), skip function inline.' % len(self.funcs)
        return self.instrs
