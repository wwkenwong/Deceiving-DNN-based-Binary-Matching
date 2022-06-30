from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *
from junkcodes import get_junk_codes


obfs_proportion = 0.08


class bb_flatten_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.fb_tbl = fb_tbl
        self.funcs = funcs
        self.cfg_tbl = cfg_tbl

    @staticmethod
    def is_flattenable_cfg(cfg):
        acc = True
        f, v = cfg
        for t in v:
            if t is not None and not acc:
                return False
            elif len(t) == 2 and len(t[1]) == 2:
                if t[1][1] is None:
                    return False
                elif t[1][1] == 'T':
                    return False
        return True

    def flatten_cfg(self, cfg):
        fname, _ = cfg
        bbl = self.fb_tbl[fname]
        name_eloc_dict = {}
        for b in bbl:
            name_eloc_dict[b.bblock_name] = b.bblock_end_loc

        f = None
        for _f in self.funcs:
            '''
            Fname S_0x804985D
            self name set_suffix_length@0x804985D-0x8049A4A
            '''
            if _f.func_name == fname:
                f = _f
                break
            elif "@" in str(_f):
                tmp_f = str(_f)
                tmp_f = tmp_f.split("@")[-1]
                tmp_f = str(tmp_f.split("-")[0])
                tmp_f = "S_"+tmp_f
                if tmp_f  == fname:
                    f = _f
                    break 

        assert f is not None
        func_instrs = self.func_instrs(f)
        for i in func_instrs:
            op = get_op(i)
            if op in JumpOp:
                des = get_cf_des(i)
                if isinstance(des, Label):
                    i0_loc = get_loc(i)
                    i1_loc = self._get_loc(i)
                    i1_loc.loc_label = ''
                    i0 = TripleInstr((self._ops['mov'], Label('global_des'), Label('$' + des), i0_loc, None))
                    junk = get_junk_codes(i1_loc)
                    i1 = DoubleInstr((op, Label('switch_bb'), i1_loc, None))
                    self.replace_instrs(i0, get_loc(i), i)
                    for _i in junk:
                        self.append_instrs(_i, get_loc(i))
                    self.append_instrs(i1, get_loc(i))
        self.update_process()

    def bb_div_flatten(self):
        cfgs = []
        for cfg in self.cfg_tbl:
            if self.is_flattenable_cfg(cfg):
                cfgs.append(cfg)
        if len(cfgs) <= 0:
            #print 'no flattenable block, quit'
            raise Exception('no flattenable block, quit')
            #return
        #cfg = cfgs[random.randint(0, len(cfgs) - 1)]
        #self.flatten_cfg(cfg)
        for cfg in cfgs:
            #if random.random() < obfs_proportion:
            if cfg[0] in self.fb_tbl.keys():
                self.flatten_cfg(cfg)
        self.insert_switch_routine()

    def get_switch_routine(self, loc):
        loc_without_label = copy.deepcopy(loc)
        loc_without_label.loc_label = ''
        junk = get_junk_codes(loc)
        i0 = DoubleInstr((self._ops['jmp'], Label('*global_des'), loc_without_label, None))
        junk.append(i0)
        # note junk can be length 0, the label modification must locate after the appending
        junk[0][-2].loc_label = ".globl switch_bb\nswitch_bb:"
        return junk

    def insert_switch_routine(self):
        bb_starts = []
        for i in range(len(self.instrs)):
            if get_op(self.instrs[i]) in ControlOp and 'ret' in p_op(self.instrs[i]):
                # Note: do not use 'jmp', because it may result in collision with bb_branchfunc_diversify
                bb_starts.append(i + 1)
        selected_idx = random.randint(0, len(bb_starts) - 1)
        selected_i = self.instrs[bb_starts[selected_idx]]
        # the location of switch routines should be carefully selected
        selected_loc = get_loc(selected_i)
        routine = self.get_switch_routine(selected_loc)
        for ins in routine:
            self.insert_instrs(ins, selected_loc)
        self.update_process()

    def visit(self, instrs):
        self.instrs = copy.deepcopy(instrs)
        self.bb_div_flatten()
        return self.instrs
