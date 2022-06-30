from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *
from junkcodes import get_junk_codes


obfs_proportion = 0.5


class bb_reorder_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.fb_tbl = fb_tbl

    def add_label(self, i):
        l = get_loc(i)
        l_ = Loc(l.loc_label + dec_hex(l.loc_addr), l.loc_addr, True)
        set_loc(i, l_)

    def print_block(self, b):
        il = self.bb_instrs(b)
        for i in il:
            print pp_print_instr(i)
        print ''

    def update_preceeding_bb(self, pb, b):
        pb_l = self.bb_instrs(pb)
        last_i = pb_l[-1]
        last_loc = self._get_loc(last_i)
        b_l = self.bb_instrs(b)
        first_i = b_l[0]
        first_loc = self._get_loc(first_i)
        bn = b.bblock_name
        assert bn is not None
        last_loc.loc_label = ''
        i = DoubleInstr(('jmp', Types.Label(bn), last_loc, False))
        # print 'update_preceeding_bb:\t' + pp_print_instr(i)
        # print 'pre'
        # self.print_block(pb)
        # print 'cur'
        # self.print_block(b)

        # junk = get_junk_codes(last_loc)
        # for j in junk:
        #     self.insert_instrs(j, first_loc)
        self.insert_instrs(i, first_loc)

    def update_succeeding_bb(self, b, sb):
        b_l = self.bb_instrs(b)
        sb_l = self.bb_instrs(sb)
        last_i = b_l[-1]
        first_i = sb_l[0]
        loc = self._get_loc(last_i)
        sloc = self._get_loc(first_i)
        sbn = sb.bblock_name
        assert sbn is not None
        loc.loc_label = ''
        i = DoubleInstr(('jmp', Types.Label(sbn), loc, False))

        # print 'update_succeeding_bb:\t' + pp_print_instr(i)
        # print 'cur'
        # self.print_block(b)
        # print 'suc'
        # self.print_block(sb)

        # junk = get_junk_codes(sloc)
        # for j in junk:
        #     self.insert_instrs(j, sloc)
        self.insert_instrs(i, sloc)

    def update_current_bb(self, fb, last_loc, sb):
        fb_l = self.bb_instrs(fb)
        sb_l = self.bb_instrs(sb)
        fl = len(fb_l)
        sl = len(sb_l)
        if fl >= sl:
            for idx in range(fl):
                if sl <= idx:
                    floc = self._get_loc(fb_l[idx])
                    floc.loc_label = ''
                    # i = SingleInstr(('nop', floc, False))
                    # self.replace_instrs(i, floc, fb_l[idx])
                    junk = get_junk_codes(floc)
                    if len(junk) == 0:
                        junk.append(SingleInstr(('nop', floc, False)))
                    self.replace_instrs(junk[0], floc, fb_l[idx])
                    for j in junk[1:]:
                        self.append_instrs(j, floc)
                elif idx < sl:
                    # Note: the get_loc return the reference of loc, which may cause side effect
                    floc = self._get_loc(fb_l[idx])
                    sloc = self._get_loc(sb_l[idx])
                    floc.loc_label = sloc.loc_label
                    sh_ = set_loc(sb_l[idx], floc)
                    self.replace_instrs(sh_, floc, fb_l[idx])
        else:
            for idx in range(sl):
                if idx >= fl:
                    sloc = self._get_loc(sb_l[idx])
                    last_loc.loc_label = sloc.loc_label
                    sh_ = set_loc(sb_l[idx], last_loc)
                    self.insert_instrs(sh_, last_loc)
                elif idx == fl - 1:
                    loc = self._get_loc(fb_l[idx])
                    sloc = self._get_loc(sb_l[idx])
                    loc.loc_label = sloc.loc_label
                    sh_ = set_loc(sb_l[idx], loc)
                    self.replace_instrs(sh_, loc, fb_l[idx])
                else:
                    floc = self._get_loc(fb_l[idx])
                    sloc = self._get_loc(sb_l[idx])
                    floc.loc_label = sloc.loc_label
                    sh_ = set_loc(sb_l[idx], floc)
                    self.replace_instrs(sh_, floc, fb_l[idx])

    def reorder_bb(self, n1, n2, bl):
        f_pre_b, f_b, f_suc_b = bl[n1], bl[n1 + 1], bl[n1 + 2]
        s_pre_b, s_b, s_suc_b = bl[n2], bl[n2 + 1], bl[n2 + 2]

        # print 'switch block %s <-> %s' % (f_b.bblock_name, s_b.bblock_name)

        self.update_preceeding_bb(f_pre_b, f_b)
        self.update_preceeding_bb(s_pre_b, s_b)

        self.update_succeeding_bb(f_b, f_suc_b)
        self.update_succeeding_bb(s_b, s_suc_b)

        self.update_process()

        self.update_current_bb(f_b, f_suc_b.bblock_begin_loc, s_b)
        self.update_current_bb(s_b, s_suc_b.bblock_begin_loc, f_b)

        self.update_process()

    def bb_div_reorder(self):
        for f in self.fb_tbl.keys():
            bl = self.fb_tbl[f]
            if len(bl) > 3:
                #if random.random() < obfs_proportion:
                if True: 
                    n1, n2 = self.get_2_diff_randint(0, len(bl) - 3)
                    self.reorder_bb(n1, n2, bl)

    def visit(self, instrs):
        print 'start bb reorder'
        self.instrs = copy.deepcopy(instrs)

        # for f in self.fb_tbl.keys():
        #     bl = self.fb_tbl[f]
        #     print 'func: %s' % f
        #     for b in bl:
        #         il = self.bb_instrs(b)
        #         for i in il:
        #             print pp_print_instr(i)
        self.bb_div_reorder()
        return self.instrs
