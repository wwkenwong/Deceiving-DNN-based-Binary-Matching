from disasm import Types
from utils.ail_utils import ELF_utils, unify_int_list, dec_hex, get_loc


class lib32_helper(object):
    """
    Manage PC relative code for x86 32bit binaries
    """

    def __init__(self, instrs, funcs):
        """
        :param instrs: instruction list
        :param funcs: function list
        """
        self.instrs = instrs
        self.funcs = {f.func_begin_addr: f.func_end_addr for f in funcs if f.func_begin_addr != 0}
        self.funcs = sorted(self.funcs.iteritems(), key=lambda e: e[0])
        self.label = []
        self.sec = []
        self.curr_func = 0
        self.curr_regs = set()  # Set of the register holding .got.plt address
        self.gotaddr = 0
        self.section_collect()

    def match_get_pc_thunk(self, instr):
        """
        Check if insturction after pcthunk invocation
        :param instr: instruction tuple
        :return: True on success
        """
        return isinstance(instr[2], Types.Label) \
            and instr[0].upper().startswith('ADD') \
            and instr[2] == '$_GLOBAL_OFFSET_TABLE_'

    def v_exp(self, e):
        """
        Check if PC relative expression and transform using labels
        :param e: expression
        :return: transformed expression if matching, original one otherwise
        """
        if isinstance(e, (Types.BinOP_PLUS, Types.BinOP_MINUS)):
            r1, addr = e
            if r1.upper() in self.curr_regs:
                addr = -addr if isinstance(e, Types.BinOP_MINUS) else addr
                des = self.gotaddr + addr
                s = self.check_sec(des)
                if s is not None:
                    self.label.append(des)
                    return Types.Label('S_' + dec_hex(des))
        return e

    def scan(self):
        """
        Scan instruction list and modify PC relative code with labels
        """
        i = 0
        inlen = len(self.instrs) - 1
        while i < inlen:
            h1 = self.instrs[i]
            if get_loc(h1).loc_addr >= self.funcs[self.curr_func][1]:
                # It can be assumed that the base register is set only inside a single function
                self.curr_func += 1
                self.curr_regs.clear()
            if isinstance(h1, Types.TripleInstr) and (self.match_get_pc_thunk(h1) \
              or (h1[0].upper() == 'MOV' and isinstance(h1[2], Types.RegClass) \
              and h1[2].upper() in self.curr_regs and isinstance(h1[1], Types.RegClass))):
                # .got.plt address can also be copied to more than one register
                self.curr_regs.add(h1[1].upper())
            elif len(self.curr_regs) > 0:
                if isinstance(h1, Types.DoubleInstr):
                    self.instrs[i] = Types.DoubleInstr((h1[0], self.v_exp(h1[1]), h1[2], h1[3]))
                elif not isinstance(h1, Types.SingleInstr):
                    if isinstance(h1, Types.TripleInstr):
                        self.instrs[i] = Types.TripleInstr((h1[0], self.v_exp(h1[1]), self.v_exp(h1[2]), h1[3], h1[4]))
                    elif isinstance(h1, Types.FourInstr):
                        self.instrs[i] = Types.FourInstr((h1[0], h1[1], self.v_exp(h1[2]), h1[3], h1[4], h1[5]))
                    if isinstance(h1[1], Types.RegClass) and h1[1].upper() in self.curr_regs:
                        # Remove if overridden
                        self.curr_regs.remove(h1[1].upper())
            i += 1

    def traverse(self):
        """
        Analyze and modify instructions
        :return: list of generated labels
        """
        if ELF_utils.elf_32() and not ELF_utils.elf_arm():
            self.scan()
        return unify_int_list(self.label)

    def get_instrs(self):
        """
        Get instruction list
        """
        return self.instrs

    def section_collect(self):
        """
        Load sections information
        """
        with open('sections.info') as f:
            def mapper(l):
                items = l.split()
                return Types.Section(items[0], int(items[1], 16), int(items[3], 16))
            self.sec = map(mapper, f)
        with open('gotplt.info') as f:
            self.gotaddr = int(f.readline().split()[1], 16)

    def check_sec(self, addr):
        """
        Find the section an address belongs to
        :param addr: address
        :return: section object, None on failure
        """
        for h in self.sec:
            b = h.sec_begin_addr
            e = b + h.sec_size
            if b <= addr < e: return h
        return None
