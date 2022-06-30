from Parser import parse
from func_slicer import func_slicer
from utils.pp_print import pp_print_instr
from disasm.Parser import InvalidOpException
from utils.ail_utils import unify_funclist_by_name, unify_funclist_by_addr, int_of_string_opt


class AilParser(object):
    """
    Load assembler dump, parse instruction and evaluate function definitions
    """

    def __init__(self):
        self.instrs = []
        self.funcs = []
        self.secs = []

    def set_funcs(self, funcs):
        """
        Set function list
        :param funcs: function list
        """
        self.funcs = funcs

    def update_func_info(self, fl):
        """
        Adjust duplicate function definitions
        :param fl: function list
        """
        for i in range(len(fl)-1):
            if fl[i].func_begin_addr == fl[i+1].func_begin_addr:
                if 'S_0x' in fl[i].func_name:
                    fl[i+1].func_end_addr = fl[i].func_end_addr
                elif 'S_0x' in fl[i+1].func_name:
                    fl[i].func_end_addr = fl[i+1].func_end_addr
        return fl

    def get_funcs(self):
        """
        Get function list
        """
        fl = unify_funclist_by_name(self.func_slicing())
        fl.sort(cmp=lambda f1, f2: f1.func_begin_addr - f2.func_begin_addr)
        fl = self.filter_func_by_name(fl)
        fl = self.update_func_info(fl)
        fl = self.filter_func_by_secs(fl)
        return unify_funclist_by_addr(fl)

    def filter_func_by_name(self, funcs):
        """
        Filter out function with undesired names
        :param funcs: function list
        """
        return filter(lambda f: '.text' not in f.func_name and f.func_name[:3] != '..@', funcs)

    def filter_func_by_secs(self, funcs):
        """
        Filter out bad functions
        :param funcs: list of functions
        """
        with open('text_sec.info') as f:
            l = f.readline()
        items = l.split()
        addr = int(items[1], 16)
        end = addr + int(items[3], 16)
        def fil(f):
            if f.func_begin_addr == 0: return False
            if len(f.func_name) < 3: return True
            opt = int_of_string_opt(f.func_name[2:], 16)
            return True if opt is None else (addr <= opt < end)
        return filter(fil, funcs)

    def func_slicing(self):
        """
        Evaluate function boundaries and get function list
        """
        fs = func_slicer(self.instrs, self.funcs)
        fs.update_text_info()
        fs.update_func()
        return fs.get_funcs()

    def set_secs(self, secs):
        """
        Set section list
        :param secs: section list
        """
        self.secs = secs

    def processInstrs(self, ilist):
        """
        Process and parse instruction
        :param ilist: list of strings from instrction dump file
        :return: parsed instruction list
        :raise Exception: if unknown instructions
        """
        invalid = set()
        p = parse()
        p.set_funclist(self.funcs)
        p.set_seclist(self.secs)
        for i in ilist:
            items = filter(len, i.split(':'))
            if len(items) > 1:
                loc = items[0]
                instr = ':'.join(items[1:])
                try: self.instrs.insert(0, p.parse_instr(instr, loc))
                except InvalidOpException as e: invalid.add(e.getop())
        if len(invalid) != 0:
            raise Exception('Some instructions are not known: ' + str(invalid))
        self.funcs = p.get_funclist()

    def p_instrs(self):
        """
        Print instructions
        """
        print '\n'.join(map(pp_print_instr, self.instrs[::-1]))

    def get_instrs(self):
        """
        Get instruction list
        """
        return self.instrs[::-1]

    def get_instrs_len(self):
        """
        Get lenght of instruction list
        """
        return len(self.instrs)
