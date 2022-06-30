from disasm import Types
from utils.ail_utils import get_loc, Opcode_utils, sort_loc, get_instr_byloc, \
    get_next_bb, recover_addr_from_label
from utils.pp_print import p_exp
from visit import ailVisitor


class tb(object):
    def __init__(self, bn, baddr, eaddr):
        self.bn = bn; self.baddr = baddr; self.eaddr = eaddr


class cfg(ailVisitor):
    """
    A CFG construction impelmentation
    """

    counter = 0

    def __init__(self):
        self.cfg_table = {}
        self.cfg_bdiv_table = {}
        self.found_entry = False
        self.skip_entry = False
        self.entry_loc = Types.Loc('', 0, True)
        self.last_loc = Types.Loc('', 0, True)
        self.entry_instr = Types.SingleInstr(('NOP', Types.Loc('', 0, True), None))
        self.bb_list = []
        self.bl = []
        self.bl_sort = []

    def cfg_exp(self, e, l):
        if isinstance(e, Types.JumpDes):
            self.cfg_table[l.loc_addr] = e
        elif isinstance(e, Types.CallDes) and not e.is_lib:
            self.cfg_table[l.loc_addr] = e.func_begin_addr

    def bb_exit(self, op, exp1):
        return Opcode_utils.is_cp(op) or Opcode_utils.is_ret((op, exp1))

    def bb_entry(self, i):
        return ':' in get_loc(i).loc_label

    def help_entry(self, i):
        if self.found_entry:
            bn = 'BB_' + str(cfg.counter)
            cfg.counter += 1
            b = Types.Bblock('', bn, self.entry_loc, self.last_loc, self.entry_instr)
            self.bb_list.insert(0, b)
        self.found_entry = True
        self.entry_instr = i
        self.entry_loc = get_loc(i)
        self.last_loc = self.entry_loc
        return i

    def help_exit(self, i):
        loc = get_loc(i)
        if self.found_entry:
            self.last_loc = loc
            bn = 'BB_' + str(cfg.counter)
            cfg.counter += 1
            b = Types.Bblock('', bn, self.entry_loc, self.last_loc, self.entry_instr)
            self.bb_list.insert(0, b)
            self.found_entry = False
            self.skip_entry = True
        elif loc.loc_addr == self.end_loc.loc_addr:
            bn = 'BB_' + str(cfg.counter)
            cfg.counter += 1
            b = Types.Bblock('', bn, loc, loc, i)
            self.bb_list.insert(0, b)
        else:
            self.last_loc = loc
        return i

    def vinst(self, i):
        loc = get_loc(i)
        if self.skip_entry:
            if loc.loc_addr == self.end_loc.loc_addr:
                bn = 'BB_' + str(cfg.counter)
                cfg.counter += 1
                b = Types.Bblock('', bn, loc, loc, i)
                self.bb_list.insert(0, b)
            else:
                self.entry_loc = loc
                self.entry_instr = i
                self.found_entry = True
                self.skip_entry = False
                self.last_loc = loc
                return self.help_exit(i) if Opcode_utils.is_control_transfer_op(i[0], i[1]) else i
        elif loc.loc_addr == self.end_loc.loc_addr:
            return self.help_exit(i)
        elif self.bb_entry(i):
            self.help_entry(i)
            return self.help_exit(i) if Opcode_utils.is_control_transfer_op(i[0], i[1]) else i
        elif isinstance(i, (Types.DoubleInstr, Types.SingleInstr)) and self.bb_exit(i[0], i[1]):
            return self.help_exit(i)
        self.last_loc = loc
        return i

    def visit(self, instrs):
        self.end_loc = get_loc(instrs[-1])
        il1 = map(self.vinst, instrs)
        self.update_bl()
        self.fb_list(self.bl)
        self.bl_sort = sorted(self.bl, cmp=lambda b1,b2: b1.bblock_begin_loc.loc_addr - b2.bblock_begin_loc.loc_addr)
        self.bl_sort = map(lambda b: tb(b.bblock_name, b.bblock_begin_loc.loc_addr, b.bblock_end_loc.loc_addr), self.bl_sort)
        return il1

    def get_fbl(self):
        return self.cfg_bdiv_table

    def get_bbl(self):
        return self.bl

    def fb_list(self, bl):
        for b in bl:
            fn = b.bf_name
            e = self.cfg_bdiv_table.get(fn, [])
            e.append(b)
            self.cfg_bdiv_table[fn] = e

    def update_bl(self):
        self.bl = []
        funcs1 = sorted(self.funcs, cmp=lambda f1,f2: f1.func_begin_addr - f2.func_begin_addr)
        bls1 = sorted(self.bb_list, lambda b1,b2: b1.bblock_begin_loc.loc_addr - b2.bblock_begin_loc.loc_addr)
        i = 0; j = 0
        while True:
            if i == len(funcs1) and j < len(bls1):
                raise Exception('Bad things')
            if j == len(bls1) or i == len(funcs1): break
            hf = funcs1[i]
            hb = bls1[j]
            if hf.func_begin_addr <= hb.bblock_begin_loc.loc_addr <= hf.func_end_addr:
                hb.bf_name = hf.func_name
                self.bl.append(hb)
                j += 1
            else:
                i += 1

    def bbn_byloc(self, addr):
        l = 0; r = len(self.bl_sort)-1
        while l <= r:
            mid = l + (r - l) / 2
            fmid = self.bl_sort[mid]
            if fmid.baddr <= addr <= fmid.eaddr:
                return fmid.bn
            elif fmid.baddr < addr:
                l = mid + 1
            else: r = mid - 1
        assert(False)

    def next_bb(self, bnl, bn):
        bn1 = get_next_bb(bn)
        return bn1 if bn1 in bnl else 'INTER'

    def recover_cfg(self):
        def aux(bnl, acc, i):
            if isinstance(i, Types.SingleInstr) and Opcode_utils.is_ret((i[0], i[1])):
                bn = self.bbn_byloc(get_loc(i).loc_addr)
                acc.insert(0, (bn, (Types.J(), 'RET')))
            elif isinstance(i, Types.DoubleInstr):
                if Opcode_utils.is_indirect(i[1]):
                    bn = self.bbn_byloc(get_loc(i).loc_addr)
                    acc.insert(0, (bn, (Types.J(), 'T')))
                elif Opcode_utils.is_call(i[0]):
                    bn = self.bbn_byloc(get_loc(i).loc_addr)
                    bn1 = self.next_bb(bnl, bn)
                    acc.insert(0, (bn, (Types.J(), bn1)))
                    acc.insert(0, (bn, (Types.J(), 'INTER')))
                elif Opcode_utils.is_jmp(i[0]):
                    bn = self.bbn_byloc(get_loc(i).loc_addr)
                    if Opcode_utils.is_func(i[1]):
                        acc.insert(0, (bn, (Types.J(), 'INTER')))
                    else:
                        en = recover_addr_from_label(p_exp(i[1]))
                        if en == -1:
                            acc.insert(0, (bn, (Types.J(), 'T')))
                        else:
                            dn = self.bbn_byloc(en)
                            acc.insert(0, (bn, (Types.J(), dn)))
                elif Opcode_utils.is_cond_jmp(i[0]):
                    if not Opcode_utils.is_func(i[1]):
                        bn = self.bbn_byloc(get_loc(i).loc_addr)
                        sn = self.next_bb(bnl, bn)
                        acc.insert(0, (bn, (Types.F(), sn)))
                    else: assert(False)
            else:
                bn = self.bbn_byloc(get_loc(i).loc_addr)
                dn = self.next_bb(bnl, bn)
                acc.insert(0, (bn, (Types.F(), dn)))
            return acc

        res = []
        for f, bl in self.cfg_bdiv_table.iteritems():
            bnl = map(lambda b: b.bblock_name, bl)
            cfg_l = sort_loc(map(lambda b: b.bblock_end_loc, bl))
            cfg_l = get_instr_byloc(self.instrs, cfg_l)
            cfg_l = reduce(lambda a,b: aux(bnl, a, b), cfg_l, [])
            res.insert(0, (f, cfg_l))
        return res

    def print_cfg_graph(self, cfg_t):
        # stub
        pass

    def get_cfg_table(self, instr_list):
        self.instrs = instr_list
        return self.recover_cfg()
