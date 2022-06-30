import copy
import random

from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *

count = 0


class instr_update(enumerate):
    INSERT = 0
    REPLACE = 1
    APPEND = 2


class ailVisitor(object):

    def __init__(self):
        self.instrs = []
        self.funcs = []
        self.secs = []

        self.fb_tbl = {}
        self.cfg_tbl = []
        self.instrs_update = []
        self.locs_update = []

        self._regs = []
        self._stack_regs = {}
        self._ops = {}
        if ELF_utils.elf_32():
            self._regs = [Types.RegClass('EAX'), Types.RegClass('EBX'), Types.RegClass('ECX'), Types.RegClass('EDX')]
            self._stack_regs['bp'] = Types.RegClass('EBP')
            self._stack_regs['sp'] = Types.RegClass('ESP')

            self._ops['mov'] = 'movl'
            self._ops['call'] = 'call'
            self._ops['jmp'] = 'jmp'
            self._ops['pop'] = 'popl'
            self._ops['push'] = 'pushl'
            self._ops['nop'] = 'nop'
            self._ops['xchg'] = 'xchg'
            self._ops['shl'] = 'shl'
            self._ops['imul'] = 'imul'
            self._ops['pushf'] = 'pushfw'
            self._ops['popf'] = 'popfw'

        elif ELF_utils.elf_64():
            self._regs = [Types.RegClass('RAX'), Types.RegClass('RBX'), Types.RegClass('RCX'), Types.RegClass('RDX')]
            self._stack_regs['bp'] = Types.RegClass('RBP')
            self._stack_regs['sp'] = Types.RegClass('RSP')

            self._ops['mov'] = 'movq'
            self._ops['call'] = 'callq'
            self._ops['jmp'] = 'jmpq'
            self._ops['pop'] = 'popq'
            self._ops['push'] = 'pushq'
            self._ops['nop'] = 'nop'
            self._ops['xchg'] = 'xchg'
            self._ops['shl'] = 'shl'
            self._ops['imul'] = 'imul'
            self._ops['pushf'] = 'pushfq'
            self._ops['popf'] = 'popfq'

        self._main_func_info = None

    def vinst(self, instr):
        return instr

    def v_exp(self, exp):
        return exp

    def set_funcs(self, funcs):
        self.funcs = funcs

    def set_secs(self, secs):
        self.secs = secs

    def visit(self, instrs):
        return map(self.vinst, instrs)

    def set_fb_tbl(self, fb):
        self.fb_tbl = fb

    def set_cfg_tbl(self, cfg):
        self.cfg_tbl = cfg

    @staticmethod
    def dec_hex(s):
        return "0x%x" % s

    @staticmethod
    def _get_loc(instr):
        return copy.deepcopy(get_loc(instr))

    @staticmethod
    def get_2_diff_randint(a, b):
        """
        return 2 different integers in the range of [a, b] (inclusive)
        """
        assert (a < b), 'the input parameters are not proper! (%d, %d)' % (a, b)
        n1 = random.randint(a, b)
        n2 = n1
        while n2 == n1:
            n2 = random.randint(a, b)
        return n1, n2

    def is_main(self, n):
        """
        Note: initial self.funcs first
        :param n: the index
        """
        t = self.funcs[n]
        if self._main_func_info is None:
            c = read_file("main.info")
            self._main_func_info = int(c[0].strip()[2:-2], 16)
        return self._main_func_info == t.func_begin_addr or self._main_func_info == t.func_end_addr

    def insert_instrs(self, i, l):
        """
        The instruction needs to be inserted into self.instrs
        Note: while calling insert and replace to modify self.instrs,
            if the location of inserted instruction is the same as that of replaced instruction,
            the replace_instrs must be called later than insert_instrs (and no 2 replace operations with the same location)
            In similar way, the append instrs must be called later than replace_instrs
        :param i: the instruction
        :param l: the location to insert the instruction
        Note: you have to call update_process to do real insertion
        """
        self.instrs_update.append((i, l, instr_update.INSERT, ""))

    def replace_instrs(self, i_new, l, i_old):
        """
        The instruction needs to be replaced
        Note: while calling insert and replace to modify self.instrs,
            if the location of inserted instruction is the same as that of replaced instruction,
            the replace_instrs must be called later than insert_instrs (and no 2 replace operations with the same location)
            In similar way, the append instrs must be called later than replace_instrs
        :param i_new: the new instruction to replace old one
        :param l: the location of instruction needs to be replaced
        :param i_old: the instruction to be replaced
        Note: you have to call update_process to do real change
        """
        i_old_str = pp_print_instr(i_old)
        self.instrs_update.append((i_new, l, instr_update.REPLACE, i_old_str))

    def append_instrs(self, i, loc):
        """
        Append the instruction i at the place behind loc
        Note: if the location is the same as another location used by replace_instrs, it must be called later than that replace_instrs
        :param i: the instruction to append
        :param loc: the location to append
        """
        self.instrs_update.append((i, loc, instr_update.APPEND, ""))

    def update_instrs(self):
        """
        do the real modification on instructions list
        Note:
            1. before doing the modification, self.instrs_update needs to be arranged in order, see self.update_process
            2. after doing the modification, the self.instrs_update needs to be cleared, see self.update_process
        """
        def same(loc1, loc2):
            return loc1.loc_addr == loc2.loc_addr

        if len(self.instrs_update) == 0:
            return self.instrs

        global count
        count += 1
        # print 'update instructions times: %d' % count
        acc = []

        iu_idx = 0
        i_idx = 0
        begin_no_change_idx = -1
        while iu_idx < len(self.instrs_update):
            if i_idx >= len(self.instrs):
                assert False, 'error in update_instrs'
            else:
                h = self.instrs[i_idx]
                i, loc1, ty, i_s = self.instrs_update[iu_idx]
                loc2 = get_loc(h)
                if same(loc1, loc2):
                    if begin_no_change_idx >= 0:
                        acc.extend(self.instrs[begin_no_change_idx:i_idx])
                        begin_no_change_idx = -1
                    if ty == instr_update.REPLACE:
                        h_s = pp_print_instr(h)
                        if i_s == h_s:
                            self.instrs[i_idx] = i
                            iu_idx += 1
                        else:
                            i_idx += 1
                            acc.append(h)
                    elif ty == instr_update.INSERT:
                        acc.append(i)
                        iu_idx += 1
                    elif ty == instr_update.APPEND:
                        acc.append(h)
                        i_idx += 1
                        # to append following instructions
                        while ty == instr_update.APPEND and same(loc1, loc2):
                            acc.append(i)
                            iu_idx += 1
                            if iu_idx < len(self.instrs_update):
                                i, loc1, ty, i_s = self.instrs_update[iu_idx]
                            else:
                                ty = None
                else:
                    if begin_no_change_idx < 0:
                        begin_no_change_idx = i_idx
                    i_idx += 1
        if begin_no_change_idx >= 0:
            acc.extend(self.instrs[begin_no_change_idx:])
        else:
            acc.extend(self.instrs[i_idx:])
        return acc

    def update_locs(self):
        self.locs_update.reverse()
        acc = []
        ii = 0
        il = 0
        while il < len(self.locs_update):
            if ii < len(self.instrs):
                ih = self.instrs[ii]
                lh = self.locs_update[il]
                lo = get_loc(ih)
                if lo.loc_addr == lh.loc_addr:
                    tmp_loc = Loc(lo.loc_label + '\n' + lh.loc_label, lo.loc_addr, True)
                    ih_ = set_loc(ih, tmp_loc)
                    ii += 1
                    il += 1
                    acc.append(ih_)
                else:
                    ii += 1
                    acc.append(ih)
            else:
                assert False, 'error in update_locs'
        acc.extend(self.instrs[ii:])
        return acc

    def update_process(self):
        # sort instrcutions by pairs of address and operation (INSERT(0), REPLACE(1), APPEND(2))
        self.instrs_update = sorted(self.instrs_update, key=lambda k: (k[1].loc_addr, k[2]))
        self.instrs = self.update_instrs()
        self.instrs_update = []

    def bb_instrs(self, b):
        """
        get the instruction list of the basic block
        :param b: the basic block needs to disassemble
        :return: the instructions list of 'b'
        """
        b_addr = b.bblock_begin_loc.loc_addr
        e_addr = b.bblock_end_loc.loc_addr
        b_idx = self._binary_search_instr_idx(b_addr, True)
        e_idx = self._binary_search_instr_idx(e_addr, False)
        assert b_idx >= 0 and e_idx >= 0 and b_idx <= e_idx, 'wrong block info (%d, %d)' % (b_idx, e_idx)
        res = self.instrs[b_idx:(e_idx + 1)]
        return res

    def _binary_search_instr_idx(self, addr, is_begin=True):
        # the address of an instruction may be duplicated by modification
        # if we need to find begin address, find the first instruction idx; otherwise, find the last one.
        res = -1
        left = 0
        right = len(self.instrs) - 1
        while left < right - 1:
            mid = (left + right) / 2
            loc = get_loc(self.instrs[mid])
            if loc.loc_addr > addr:
                right = mid
            elif loc.loc_addr < addr:
                left = mid
            else:
                res = mid
                break
        if get_loc(self.instrs[left]).loc_addr == addr:
            res = left
        elif get_loc(self.instrs[right]).loc_addr == addr:
            res = right
        if res < 0:
            return -1
        if is_begin:
            while res > 0 and get_loc(self.instrs[res - 1]).loc_addr == addr:
                res -= 1
        else:
            while res < len(self.instrs) - 1 and get_loc(self.instrs[res + 1]).loc_addr == addr:
                res += 1
        return res

    def func_instrs(self, f):
        """
        get the instruction list of the function
        :param f: the function needs to disassemble
        :return: the instructions list of 'f'
        """
        b_addr = f.func_begin_addr
        e_addr = f.func_end_addr
        b_idx = self._binary_search_instr_idx(b_addr, True)
        e_idx = self._binary_search_instr_idx(e_addr, False)
        assert b_idx >= 0 and e_idx >= 0 and b_idx <= e_idx, 'wrong function info (%d, %d)' % (b_idx, e_idx)
        if b_idx < e_idx:
            res = self.instrs[b_idx:e_idx]
        else:
            res = [self.instrs[b_idx]] # some bugs during analysing, I have to do this werid stuff
        assert len(res) != 0, 'error: a function without any instruction ' + str(f)
        return res

    def print_func(self, f):
        fl = self.func_instrs(f)
        res = 'func_name: ' + f.func_name + '\n'
        for i in fl:
            res += pp_print_instr(i) + '\n'
        print res
