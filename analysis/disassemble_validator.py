import config
from disasm import Types
from termcolor import colored
from utils.ail_utils import get_loc, Opcode_utils


class stack_of_loc(object):
    def __init__(self):
        self.loclist = []
    def push(self, x):
        self.loclist.append(x)
    def pop(self):
        return self.loclist.pop()
    def peek(self):
        return self.loclist[-1]
    def size(self):
        return len(self.loclist)

class simple_queue(object):
    def __init__(self):
        self.queue = []
    def add(self, elem):
        self.queue.append(elem)
    def get(self):
        return self.queue.pop(0)
    def size(self):
        return len(self.queue)
    def exists(self, func):
        return any(map(func, self.queue))


def is_des(e):
    """
    Get address from symbolic expression
    :param e: expression
    :return: integer address if jump or call constant target, None otherwise
    """
    if isinstance(e, Types.JumpDes): return e
    elif isinstance(e, Types.CallDes) and not e.is_lib:
        try: return int(e.func_name[2:], 16)
        except: return None
    return None


class dis_validator(object):
    """
    Checks for disassembly errors:
    - invalid instructions
    - invalid control transfers destinations
    """

    icf_stack = stack_of_loc()

    def __init__(self):
        self.looking_for_cfd = False
        self.text_secs = []
        self.locs = []
        self.up_bound = Types.Loc('', 0, True)
        self.low_bound = Types.Loc('', 0, True)
        self.trim_tbl = {}
        self.five_q = simple_queue()

    def text_sec_collect(self):
        """
        Load .text section info
        """
        def secmapper(l):
            items = l.split()
            return (int(items[1], 16), int(items[3], 16))
        with open('text_sec.info') as f:
            self.text_secs = map(secmapper, f)
        with open('init_sec.info') as f:
            self.text_secs += map(secmapper, f)

    def invalid_opcode(self, instr):
        """
        Check for bad instruction disassembly (x86 only)
        :param instr: instruction tuple
        :return: True if invalid
        """
        return instr[0] in Types.ErrorOp

    def invalid_transfer(self, instr):
        """
        Check if instruction is a branch and its target is valid
        :param instr: instruction tuple
        :return: True if invalid
        """
        is_outside = lambda d: all(map(lambda e: d < e[0] or d >= e[0] + e[1], self.text_secs))
        if isinstance(instr, Types.DoubleInstr) and Opcode_utils.is_cp(instr[0]):
            res = is_des(instr[1])
            return False if res is None else is_outside(res)
        return False

    def visit(self, instrlist):
        """
        Check disassbled code
        :param instrlist: list of instruction objects
        """
        self.text_sec_collect()
        self.locs = filter(lambda i: self.invalid_opcode(i) or self.invalid_transfer(i), instrlist)
        self.locs = map(lambda i: get_loc(i).loc_addr, self.locs)
        if len(self.locs) != 0:
            if config.arch == config.ARCH_ARMT:
                print colored('     Warning:', 'yellow'), 'instructions at this locations were probably misinterpreted:'
                print '     ' + str(map(hex, self.locs))
            else:
                print map(hex, self.locs)
                exit()
                self.validate(instrlist)

    def trim_results(self):
        return self.trim_tbl.items()

    def update_trimtbl(self, b, e):
        if b in self.trim_tbl:
            if e > self.trim_tbl[b]: self.trim_tbl[b] = e

    def is_icf(self, p, e):
        if e is None: return False
        return Opcode_utils.is_cp(p) and isinstance(e, Types.StarDes)

    def update_cfd(self, index, instrlist):
        if not self.looking_for_cfd: return
        tl = instrlist[index:index+5]
        inv = lambda i: get_loc(i).loc_addr in self.locs
        if not any(map(inv, tl)):
            self.looking_for_cfd = False
            self.update_trimtbl(self.up_bound.loc_addr, get_loc(tl[0]).loc_addr)

    def update_cft_track(self, i):
        self.five_q.add(i)
        if self.five_q.size() == 6: self.five_q.get()

    def update_cft_stack(self, instr):
        inv = lambda i: get_loc(i).loc_addr in self.locs
        if not self.five_q.exists(inv):
            dis_validator.icf_stack.push(get_loc(instr))

    def validate(self, instrlist):
        self.five_q = simple_queue()
        for (index, i) in enumerate(instrlist):
            loc = get_loc(i)
            if loc.loc_addr in self.locs:
                self.up_bound = dis_validator.icf_stack.pop()
                self.looking_for_cfd = True
            else:
                if len(loc.loc_label) > 1:
                    self.update_cfd(index, instrlist)
                    self.update_cft_track(i)
                else:
                    p = i[0]
                    e = i[1] if isinstance(i, Types.DoubleInstr) else None
                    if Opcode_utils.call_patt.match(p):  # @UndefinedVariable
                        print "detected call instruction in disassembly validator: " + str(i)
                        self.update_cfd(index + 1, instrlist)
                        if self.is_icf(p, e): self.update_cft_stack(i)
                    elif self.is_icf(p, e):
                        self.update_cft_stack(i)
                    self.update_cft_track(i)
