import Types
import init_sec_adjust
from Types import Func
from utils.ail_utils import read_file, unify_int_list, get_loc, dec_hex


class func_slicer(object):
    """
    Function boundary evaluation
    """

    def __init__(self, instrs, funcs):
        """
        :param instrs: list of instructions
        :param funcs: list of function objects
        """
        self.instrs = instrs
        self.funcs = funcs
        self.baddr = -1
        self.eaddr = -1
        self.label = ''
        self.func_begins = []
        self.text_b_addr = 0
        self.text_e_addr = 0
        self.func_set = {}

    def update(self):
        func = 'S_' + dec_hex(self.baddr)
        if func in self.func_set:
            self.func_set[func].func_begin_addr = self.baddr
            self.func_set[func].func_end_addr = self.eaddr
            self.func_set[func].is_lib = False
        else:
            f1 = Func(func, self.baddr, self.eaddr, False)
            self.func_set[func] = f1

    def filter_addr_by_secs(self, bl):
        """
        Filter out addresses in bad sections
        :param bl: address list
        """
        init_sec_adjust.main()
        with open('init_sec.info') as f:
            l = f.readline()
        items = l.split()
        baddr = int(items[1], 16)
        eaddr = baddr + int(items[3], 16)
        return filter(lambda n: n < baddr or n >= eaddr, bl)

    def update_text_info(self):
        """
        Load .text section info
        """
        with open('text_sec.info') as f:
            l = f.readline()
        items = l.split()
        self.text_b_addr = int(items[1], 16)
        self.text_e_addr = int(items[3], 16)

    def build_func_info(self):
        """
        Evaluate function boundaries
        """
        self.func_begins = unify_int_list(self.func_begins)
        self.func_begins = self.filter_addr_by_secs(self.func_begins)
        for i in range(len(self.func_begins)-1):
            self.baddr = self.func_begins[i]
            self.eaddr = self.func_begins[i+1]
            self.update()
        self.baddr = self.func_begins[-1]
        self.eaddr = get_loc(self.instrs[0]).loc_addr
        self.update()

    def check_text(self, e):
        """
        Check if function in .text section
        :param e: expression
        """
        if isinstance(e, Types.CallDes) and not e.is_lib:
            n = int(e.func_name[2:], 16)
            return self.text_b_addr <= n < self.text_e_addr
        return False

    def update_func(self):
        """
        Add function to function set
        """
        for e in self.funcs:
            self.func_set[e.func_name] = e

    def get_func_list(self):
        """
        Return list of function
        """
        return self.func_set.values()

    def get_funcs(self):
        """
        Evalute function info and return updated function list
        """
        self.func_begins = map(lambda a: int(a, 16), read_file('faddr.txt'))
        self.func_begins += [f.func_begin_addr for f in self.funcs if f.func_begin_addr != 0]
        self.build_func_info()
        fl = self.get_func_list()
        print '     Sliced', len(self.func_begins), 'functions'
        return fl
