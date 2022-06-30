from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *


class bb_merge_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.fb_tbl = fb_tbl
        self.cfg_tbl = cfg_tbl

    def update_1st_bb(self, b):
        bil = self.bb_instrs(b)
        last_instr = bil[-1]
        op = get_op(last_instr)
        last_loc = self._get_loc(last_instr)
        if Opcode_utils.is_jmp(op):
            new_i = SingleInstr((self._ops['nop'], last_loc, None))
            self.replace_instrs(new_i, last_loc, last_instr)
        self.update_process()
        return last_loc

    def update_2nd_bb(self, attach_loc, b):
        bil = self.bb_instrs(b)
        merge_symbol = b.bblock_name + '_merge'
        last_instr = bil[-1]

        loc_without_label = self._get_loc(last_instr)
        loc_without_label.loc_label = ''
        loc_with_label = self._get_loc(last_instr)
        loc_with_label.loc_label = merge_symbol + ': '
        i0 = DoubleInstr((self._ops['jmp'], Label(merge_symbol), loc_without_label, None))
        i1 = SingleInstr((self._ops['nop'], loc_with_label, None))

        # It should have no problem if we do not set it to no-option block
        # for i in bil:
        #     cloc = self._get_loc(i)
        #     nop_i = SingleInstr((self._ops['nop'], cloc, None))
        #     self.replace_instrs(nop_i, cloc, i)
        for i in bil:
            new_i = set_loc(i, attach_loc)
            self.append_instrs(new_i, attach_loc)
        # after finishing b1+b2, jump to merge_symbol
        # the merge_symbol points to the end of b2
        self.append_instrs(i0, attach_loc)
        self.append_instrs(i1, get_loc(last_instr))
        self.update_process()

    def print_merge_blocks(self, b1, b2):
        print 'merge basic block: %s and %s' % (b1.bblock_name, b2.bblock_name)

    def merge_bb(self, p):
        f, s, d = p
        # print 'merge block in function: %s' % f
        bbl = self.fb_tbl[f]
        tl = []
        for b in bbl:
            if b.bblock_name == s:
                tl.insert(0, b)
            elif b.bblock_name == d:
                tl.append(b)
        if len(tl) == 2:
            # self.print_merge_blocks(tl[0], tl[1])
            b1_end_loc = self.update_1st_bb(tl[0])
            self.update_2nd_bb(b1_end_loc, tl[1])
        # else:
        #     print "we found a inter-procedural jmp, which may be caused by bb_flatten\n"

    def mergeable_bb(self):
        res = []

        for f, v in self.cfg_tbl:
            sl = {}
            dl = {}
            for t in v:
                if len(t) == 2 and len(t[1]) == 2:
                    if t[1][1] is None or t[1][1] == 'T' or t[1][1] == 'INTER' or t[1][1] == 'RET':
                        continue
                    else:
                        s = t[0]
                        d = t[1][1]
                        if s not in sl.keys():
                            sl[s] = 1
                        else:
                            sl[s] += 1
                        if d not in dl.keys():
                            dl[d] = 1
                        else:
                            dl[d] += 1
            for t in v:
                if t[0] in sl.keys() and sl[t[0]] == 1 and t[1][1] in dl.keys() and dl[t[1][1]] == 1:
                    if "BB_" in t[0] and "BB_" in t[1][1]:
                        res.append((f, t[0], t[1][1]))
        return res

    def bb_div_merge(self):
        mergeable_pairs = self.mergeable_bb()
        print '%d candidate pairs' % len(mergeable_pairs)
        if len(mergeable_pairs) == 0:
            print 'do nothing'
            return
        # n = random.randint(0, len(mergeable_pairs) - 1)
        # self.merge_bb(mergeable_pairs[n])
        mergeable_pairs_appears = []
        for i in range(len(mergeable_pairs)):
            if mergeable_pairs[i][0] in self.fb_tbl.keys():
                mergeable_pairs_appears.append(mergeable_pairs[i])
        if len(mergeable_pairs_appears)>0:
            if random.random()>0.2:
                number_to_sample = random.randint(1,len(mergeable_pairs_appears))
                to_loop = random.sample(mergeable_pairs_appears,number_to_sample)
                for i in range(len(to_loop)):
                    self.merge_bb(to_loop[i])
            else:
                for i in range(len(mergeable_pairs_appears)):
                    self.merge_bb(mergeable_pairs_appears[i])
        '''
        # strategy for full binary 
        for i in range(len(mergeable_pairs)):
            # to avoid redefinition of symbols
            if i % 10 == 0:
                if mergeable_pairs[i][0] in self.fb_tbl.keys():
                    print('Merged')
                    self.merge_bb(mergeable_pairs[i])
        '''

    def visit(self, instrs):
        print 'start basic block merge ...'
        self.instrs = copy.deepcopy(instrs)
        self.bb_div_merge()
        return self.instrs
