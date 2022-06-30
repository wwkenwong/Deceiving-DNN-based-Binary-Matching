from analysis.visit import *
from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *
from junkcodes import get_junk_codes

obfs_proportion = 0.02


class bb_branchfunc_diversify(ailVisitor):

    def __init__(self, funcs, fb_tbl, cfg_tbl):
        ailVisitor.__init__(self)
        self.funcs = funcs
        self._new_des_id = 0

    def _branch_a_func(self, f):
        fil = self.func_instrs(f)
        find_a_valid_func = False
        for instr in fil:
            op = get_op(instr)
            des = get_cf_des(instr)
            if des is not None and isinstance(des, Label):
                if op in JumpOp:
                    #if random.random() > obfs_proportion:
                    #if True: 
                    #    continue
                    # here we modify the process of 2 situations, jmp and conditional jmp
                    if p_op(op) == 'jmp' or p_op(op) == self._ops['jmp']:
                        # this is a simple jump, we simply cache the des and call the routine
                        find_a_valid_func = True
                        loc = self._get_loc(instr)
                        i0 = TripleInstr((self._ops['mov'], Label('branch_des'), Label('$' + str(des)), loc, None))
                        loc1 = copy.deepcopy(loc)
                        loc1.loc_label = ''
                        i1 = DoubleInstr((self._ops['call'], Label('branch_routine'), loc1, None))
                        junk1 = get_junk_codes(loc1)
                        junk2 = get_junk_codes(loc1)

                        self.insert_instrs(i0, loc)
                        for _i in junk1:
                            self.insert_instrs(_i, loc)
                        self.replace_instrs(i1, loc, instr)
                        for _i in junk2:
                            self.append_instrs(_i, loc)
                    elif p_op(op) in {'je', 'jne', 'jl', 'jle', 'jg', 'jge'}:
                        # we only handle with these conditional jmp
                        find_a_valid_func = True
                        loc = self._get_loc(instr)
                        postfix = p_op(op)[1:]
                        # we ues conditional move the modify a conditional jmp
                        self._new_des_id += 1
                        fall_through_label = 'fall_through_label_%d' % self._new_des_id
                        loc_no_label = copy.deepcopy(loc)
                        loc_no_label.loc_label = ''
                        loc_fall_through = copy.deepcopy(loc)
                        loc_fall_through.loc_label = fall_through_label + ':'
                        tmp = [
                            DoubleInstr((self._ops['push'], self._regs[0], loc, None)),  # 0  replace
                            DoubleInstr((self._ops['push'], self._regs[1], loc_no_label, None)),
                            TripleInstr((self._ops['mov'], self._regs[0], Label('$' + fall_through_label), loc_no_label, None)),
                            TripleInstr((self._ops['mov'], self._regs[1], Label('$' + str(des)), loc_no_label, None)),
                            TripleInstr(('cmov' + postfix, self._regs[0], self._regs[1], loc_no_label, None)),
                            TripleInstr((self._ops['mov'], Label('branch_des'), self._regs[0], loc_no_label, None)),
                            DoubleInstr((self._ops['pop'], self._regs[1], loc_no_label, None)),
                            DoubleInstr((self._ops['pop'], self._regs[0], loc_no_label, None)),
                            DoubleInstr((self._ops['call'], Label('branch_routine'), loc_no_label, None)),
                            SingleInstr((self._ops['nop'], loc_fall_through, None))
                        ]
                        self.replace_instrs(tmp[0], loc, instr)
                        for _i in tmp[1:]:
                            self.append_instrs(_i, loc)
        return find_a_valid_func

    def branch_func(self):
        # print 'bb branch on %d candidate function' % len(self.funcs)
        # select the 1st obfs_proportion functions
        # for f in self.funcs[:int(obfs_proportion * len(self.funcs))]:
        do_branch = False
        for f in self.funcs:
        #for f in random.sample(self.funcs, int(obfs_proportion * len(self.funcs)) + 1):
            if self._branch_a_func(f):
                do_branch = True
                self.update_process()
        if not do_branch:
            #print 'no valid function is selected'
            raise Exception('no valid function is selected')

    def bb_div_branch(self):
        self.branch_func()

    def get_branch_routine(self, iloc):
        """
        return the list of routine instructions for branch functions
        :param iloc: the location of instruction that routine being inserted
        :return: the list of routine instructions
        """
        loc_with_branch_label = copy.deepcopy(iloc)
        loc_with_branch_label.loc_label = 'branch_routine: '
        loc = copy.deepcopy(iloc)
        loc.loc_label = ''
        i0 = DoubleInstr((self._ops['pop'], Label('global_des'), loc_with_branch_label, None))
        junk = get_junk_codes(loc)
        i1 = DoubleInstr((self._ops['jmp'], Label('*branch_des'), loc, None))
        res = [i0]
        res.extend(junk)
        res.append(i1)
        return res

    def attach_branch_routine(self):
        loc = get_loc(self.instrs[-1])
        routine_instrs = self.get_branch_routine(loc)
        self.instrs.extend(routine_instrs)

    def bb_div_process(self):
        self.bb_div_branch()
        self.attach_branch_routine()

    def visit(self, instrs):
        print 'start bb branch function'
        self.instrs = copy.deepcopy(instrs)
        self.bb_div_process()
        return self.instrs
