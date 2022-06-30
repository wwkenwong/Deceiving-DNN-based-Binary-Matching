from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *
from junkcodes import get_junk_codes


class instr_garbage_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.fb_tbl = fb_tbl

    def _nop_garbage_instrs(self, loc):
        # use insert or append to add these instructions
        # no label
        iloc = copy.deepcopy(loc)
        iloc.loc_label = ''
        res = [
            SingleInstr((self._ops['nop'], iloc, None)),
            TripleInstr((self._ops['mov'], self._stack_regs['bp'], self._stack_regs['bp'], iloc, None)),
            TripleInstr((self._ops['mov'], self._stack_regs['sp'], self._stack_regs['sp'], iloc, None)),
            TripleInstr((self._ops['xchg'], self._stack_regs['bp'], self._stack_regs['bp'], iloc, None)),
            TripleInstr((self._ops['xchg'], self._stack_regs['sp'], self._stack_regs['sp'], iloc, None))
        ]
        res.extend([
            TripleInstr((self._ops['mov'], reg, reg, iloc, None)) for reg in self._regs
        ])
        return res

    def _get_garbage(self, loc, mode=1):
        if mode == 1:
            nops = self._nop_garbage_instrs(loc)
            num_instrs = len(nops)  # random.randint(1, len(nops) - 4)
            res = []
            for i in range(num_instrs):
                res.append(random.choice(nops))
            return res
        elif mode == 2:
            return get_junk_codes(loc, None)
        else:
            return []

    def _insert_garbage(self, loc, mode=1):
        garbage = self._get_garbage(loc, mode)
        for i in garbage:
            self.insert_instrs(i, loc)

    def insert_garbage(self):
        for f in self.fb_tbl.keys():
            # select block to insert garbage
            b = random.choice(self.fb_tbl[f])
            bil = self.bb_instrs(b)
            loc = get_loc(random.choice(bil))
            self._insert_garbage(loc, mode=random.randint(1, 2))
        self.update_process()

    def visit(self, instrs):
        print 'start garbage insertion ...'
        self.instrs = copy.deepcopy(instrs)
        self.insert_garbage()
        return self.instrs
