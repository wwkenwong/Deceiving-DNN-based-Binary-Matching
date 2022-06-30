"""
Assembler parsing
"""

import re
import Types
import config
from utils.ail_utils import Opcode_utils
from lex import Lloc, Lop, Lexp, prefix_sub, lexer

class InvalidOpException(Exception):
    def getop(self):
        return self.message.split(':')[1].strip()

class base_parser(object):
    """
    Base parser class
    """

    def __init__(self):
        self.funcs = {}
        self.sec_list = []
        self.call_des = False
        self.jmp_des = False
        self.indjmp_des = False

    def set_funclist(self, l):
        """
        Set function list
        :param l: list of functions
        """
        self.funcs = {f.func_name: f for f in l}

    def get_funclist(self):
        """
        Get function list
        """
        return self.funcs.values()

    def set_seclist(self, l):
        """
        Set section list
        :param l: list of sections
        """
        self.sec_list = l

    def get_func(self, name, lib, baddr=0):
        """
        Get function objction or create a new one
        :param name: function name
        :param lib: True if library function
        :param baddr: function begin address
        :return: function object
        """
        f = self.funcs.get(name, None)
        if f is None:
            f = Types.Func(name, baddr, 0, lib)
            self.funcs[name] = f
        return f

    def get_sec(self, addr):
        """
        Get section containing address
        :param addr: address
        :return: section object or None on failure
        """
        addr = int(addr, 16)
        s = next((h for h in self.sec_list if h.sec_begin_addr <= addr < h.sec_begin_addr + h.sec_size), None)
        if s is None: raise Exception("Error in get_sec")
        return s


class parseX86(base_parser):
    """
    Parser for x86 instructions
    """

    def unptr_symb(self, s):
        """
        Parse basic indirect addressing: (%rax)
        :param s: lexeme
        """
        r = self.reg_symb(s[1:-1])
        return Types.UnOP(r) if r is not None else None

    def binptr_m_symb(self, s):
        """
        Parse addressing with register minus offset: -0x10(%rax)
        :param s: lexeme
        """
        if ',' in s or ':' in s: return None
        items = s.split('(')
        offset = items[0]
        if offset[0] != '-': return None
        reg = self.reg_symb(items[1][:-1])
        return None if reg is None else Types.BinOP_MINUS((reg, int(offset[1:], 16)))

    def binptr_p_symb(self, s):
        """
        Parse addressing with register plus offset: 0x10(%rax)
        :param s: lexeme
        """
        if ',' in s or ':' in s: return None
        items = s.split('(')
        offset = items[0]
        reg = self.reg_symb(items[1][:-1])
        return None if reg is None else Types.BinOP_PLUS((reg, int(offset, 16)))

    def threeptr_symb(self, s):
        """
        Parse addressing with base register and scaled index: (%rax, %rbx, 4)
        :param s: lexeme
        """
        if s[0] == '(' and s[-1] == ')':
            items = s[1:-1].split(',')
            if len(items) != 3: return None
            reg1 = self.reg_symb(items[0])
            reg2 = self.reg_symb(items[1])
            return None if reg1 is None or reg2 is None \
                else Types.ThreeOP((reg1, reg2, int(items[2])))
        return None

    def fourptr_m_symb(self, s):
        """
        Parse addressing with base register, scaled index and negative offset: -0x10(%rax, %rbx, 4)
        :param s: lexeme
        """
        items = s.split('(')
        offset = items[0]
        if offset[0] != '-': return None
        offset = offset[1:]
        items1 = items[1][:-1].split(',')
        if len(items1) != 3: return None
        reg1 = self.reg_symb(items1[0])
        reg2 = self.reg_symb(items1[1])
        return None if reg1 is None or reg2 is None \
            else Types.FourOP_MINUS((reg1, reg2, int(items1[2]), int(offset, 16)))

    def fourptr_p_symb(self, s):
        """
        Parse addressing with base register, scaled index and positive offset: 0x10(%rax, %rbx, 4)
        :param s: lexeme
        """
        items = s.split('(')
        offset = items[0]
        if offset[0] == '%' or offset[0] == '*': return None
        items1 = items[1][:-1].split(',')
        if len(items1) != 3: return None
        reg1 = self.reg_symb(items1[0])
        reg2 = self.reg_symb(items1[1])
        return None if reg1 is None or reg2 is None \
            else Types.FourOP_PLUS((reg1, reg2, int(items1[2]), int(offset, 16)))

    def segref_symb(self, s):
        """
        Parse addressing with segment register: %ds:0x10(%rax)
        :param s: lexeme
        """
        if ':' not in s: return None
        items = s.split(':')
        se = items[0].strip()[1:]
        if len(items) != 2 or se not in Types.Seg: return None
        return Types.SegRef((Types.SegClass(se), self.exp_symb(items[1].strip())))

    def jmptable_m_symb(self, s):
        """
        Parse addressing with scaled index and negative offset: -0x10(,%rbx, 4)
        :param s: lexeme
        """
        if '(,' not in s: return None
        tokens = s.split(',')
        if tokens[0][0] != '-': return None
        addr = tokens[0][1:-1]
        reg = self.reg_symb(tokens[1])
        off = tokens[2][:-1]
        return None if reg is None \
            else Types.JmpTable_MINUS((int(addr, 16), reg, int(off)))

    def jmptable_p_symb(self, s):
        """
        Parse addressing with scaled index and negative offset: 0x600400(,%rbx, 4)
        :param s: lexeme
        """
        if '(,' not in s: return None
        tokens = s.split(',')
        addr = tokens[0][:-1]
        reg = self.reg_symb(tokens[1])
        off = tokens[2][:-1]
        return None if reg is None \
            else Types.JmpTable_PLUS((int(addr, 16), reg, int(off)))

    def ptr_symb(self, s):
        """
        Parse indirect addressing
        :param s: lexeme
        """
        if '(' in s and ')' in s:
            mappers = [self.unptr_symb, self.binptr_m_symb, self.binptr_p_symb,
                       self.threeptr_symb, self.fourptr_m_symb, self.fourptr_p_symb,
                       self.jmptable_m_symb, self.jmptable_p_symb, self.segref_symb]
            for m in mappers:
                res = m(s)
                if res is not None: return res
        return None

    def jumpdes_symb(self, s):
        """
        Parse jump destination symbol (address or label)
        :param s: lexeme
        """
        if '+' in s or '-' in s:
            return Types.JumpDes(s.split()[0], 16)
        try: return Types.CallDes(self.calldes_symb(s))
        except AttributeError: return None

    def calldes_symb(self, s):
        """
        Parse function call destination symbol (address or label)
        :param s: lexeme
        """
        items = s.split()
        if len(items) < 2: return None
        s1 = items[1].strip()
        if '+' in s1 or '-' in s1:
            addr = int(items[0], 16)
            return self.get_func('S_0x%X' % addr, False, addr)
        elif '@' in s1:
            name = s1.split('@')[0]
            return self.get_func(name[1:], True)
        return self.get_func(s1[1:-1], True)

    def stardes_symb(self, s):
        """
        Parse indirect jump or call destination: call *%rax
        :param s: lexeme
        """
        return self.exp_symb(s[1:])

    def symbol_symb(self, s):
        """
        Parse branch destination symbol
        :param s: lexeme
        """
        s = s.strip()
        if s[0] == '*':
            return Types.StarDes(self.stardes_symb(s))
        elif self.call_des:
            return Types.CallDes(self.calldes_symb(s))
        return self.jumpdes_symb(s)

    def reg_symb(self, s):
        """
        Parse register
        :param s: lexeme
        """
        r = s[1:].upper()
        return Types.RegClass(r) if r in Types.Reg else None

    def assist_sym(self, s):
        """
        Parse assist operator
        :param s: lexeme
        """
        return Types.AssistOpClass(s) if s in Types.AssistOp else None

    def const_symb(self, s):
        """
        Parse constant
        :param s: lexeme
        """
        s = s.strip()
        try:
            if s[0] == '$': return Types.Normal(s[1:], 16)
            return Types.Point(s, 16)
        except ValueError: return None

    def exp_symb(self, s):
        """
        Parse expression symbol (constant, register, ...)
        :param s: lexeme
        """
        if s[0] == '*': return Types.StarDes(self.stardes_symb(s))
        symbf = [self.ptr_symb, self.reg_symb, self.assist_sym, self.const_symb, self.symbol_symb]
        for f in symbf:
            res = f(s)
            if res is not None: return res
        return Types.Label(s)

    def op_symb(self, sym):
        """
        Parse operator
        :param sym: lexeme
        """
        if sym not in Types.Op: raise InvalidOpException('Invalid operator: ' + sym.upper())
        if Opcode_utils.call_patt.match(sym): self.call_des = True  # @UndefinedVariable
        return sym

    def prefix_identify(self, instr):
        return 'lock ' in instr


class parseARM(base_parser):
    """
    Parser for ARM instructions
    """

    def reg_symb(self, sym):
        """
        Parse register
        :param s: lexeme
        """
        if sym in Types.Reg:
            return Types.StarDes(Types.RegClass(sym)) \
                   if self.call_des or (self.indjmp_des and sym.upper() != 'LR') \
                   else Types.RegClass(sym)
        if sym[-1] == '!' and sym[:-1] in Types.Reg:
            # vldmia r2!, {s14}
            return Types.IncReg(sym)
        return None

    def const_symb(self, sym):
        """
        Parse constant
        :param s: lexeme
        """
        if self.jmp_des: return None
        try:
            if sym[0] == '#': return Types.Normal(sym[1:], 16)
            return Types.Point(sym, 16)
        except ValueError: return None

    def unptr_symb(self, sym):
        """
        Parse basic indirect addressing: [r1]
        :param s: lexeme
        """
        r = self.reg_symb(sym[1:-1])
        return Types.UnOP(r) if r is not None else None

    def binptr_symb(self, sym):
        """
        Parse addressing with register and offset: [r1, #0x10]
        :param s: lexeme
        """
        preind = sym[-1] == '!'
        items = sym[1:(-2 if preind else -1)].split(',')
        if len(items) == 2 and items[1][0] == '#':
            off = int(items[1][1:], 16)
            return Types.BinOP_PLUS((self.reg_symb(items[0]), off), preind) if off >= 0 else \
                   Types.BinOP_MINUS((self.reg_symb(items[0]), -off), preind)
        return None

    def threeptr_symb(self, sym):
        """
        Parse addressing with base register and scaled index: [r1, r2, lsl #2]
        :param s: lexeme
        """
        items = sym[1:-1].split(',')
        if len(items) == 2: items.append('lsl|#0')
        return Types.ThreeOP((self.reg_symb(items[0]), self.reg_symb(items[1]), self.shift_symb(items[2])))

    def ptr_symb(self, sym):
        """
        Parse indirect addressing
        :param s: lexeme
        """
        if sym[0] != '[': return None
        mappers = [self.unptr_symb, self.binptr_symb, self.threeptr_symb]
        for m in mappers:
            res = m(sym)
            if res is not None: return res
        return None

    def shift_symb(self, sym):
        """
        Parse shift expression: lsl #8
        :param sym: lexeme
        """
        if sym[0] != '[' and '|' in sym:
            items = sym.split('|')
            return Types.ShiftExp(items[0], int(items[1][1:]))
        return None

    def jmpdes_symb(self, sym):
        """
        Parse jump destination symbol (address or label): b #0x10010
        :param s: lexeme
        """
        if sym[0] == '#':
            if '.' in sym: return None
            addr = int(sym[1:], 16) & (-2)
            return Types.JumpDes(addr)
        try: return Types.CallDes(self.calldes_symb(sym))
        except: return None

    def calldes_symb(self, sym):
        """
        Parse function call destination symbol (address or label)
        :param s: lexeme
        """
        items = sym.split()
        if (len(items) < 2 and items[0][0] == '#') or \
           ('+' in items[1] or '-' in items[1]):
            addr = int(items[0][1:], 16) & (-2)
            return self.get_func('S_0x%X' % addr, False, addr)
        if '@' in items[1]:
            name = items[1].split('@')[0]
            return self.get_func(name[1:], True)
        return None

    def symbol_symb(self, sym):
        """
        Parse branch destination symbol
        :param s: lexeme
        """
        return Types.CallDes(self.calldes_symb(sym)) if self.call_des else self.jmpdes_symb(sym)

    def reg_list(self, sym):
        """
        Parse regist list: {r0, r1, r2}
        :param sym: lexeme
        """
        if sym[0] == '{':
            return Types.RegList(map(Types.RegClass, sym[1:-1].split(',')))
        return None

    tb_matcher = re.compile('\((S_0x[0-9a-f]+)\-(S_0x[0-9a-f]+)\)\/2', re.I)
    def tb_symb(self, sym):
        """
        Parse jump table entry: (S_0x100400 - S_0x100100)/2
        :param sym: lexeme
        """
        m = parseARM.tb_matcher.search(sym)
        if m: return Types.TBExp(m.group(2), m.group(1))
        return None

    def exp_symb(self, s):
        """
        Parse expression symbol (constant, register, ...)
        :param s: lexeme
        """
        symbf = [self.reg_list, self.tb_symb, self.shift_symb, self.ptr_symb,
                 self.reg_symb, self.const_symb, self.symbol_symb]
        for f in symbf:
            res = f(s)
            if res is not None: return res
        return Types.Label(s)

    def op_symb(self, sym):
        """
        Parse operator
        :param sym: lexeme
        """
        if sym in Types.DataTypes: return Types.InlineData(sym)
        parts = sym.split('.')
        if (parts[0] in Types.Op or
           (parts[0][-2:] in Types.CondSuff and parts[0][:-2] in Types.Op)) and \
           all(map(lambda e: e in Types.OpQualifier, parts[1:])):
            self.jmp_des = parts[0] in Types.ControlOp or \
                           (parts[0][-2:] in Types.CondSuff and parts[0][:-2] in Types.ControlOp)
            self.call_des = Opcode_utils.call_patt.match(parts[0]) is not None  # @UndefinedVariable
            self.indjmp_des = Opcode_utils.indjmp_patt.match(parts[0]) is not None # @UndefinedVariable
            return sym
        raise InvalidOpException('Invalid operator: ' + sym.upper())

    def prefix_identify(self, instr):  # @UnusedVariable
        return False


class parse(parseARM if (config.arch == config.ARCH_ARMT) else parseX86):

    def push_stack(self, lex):
        """
        Parse a lexeme
        :param lex: lexeme
        """
        lext = lex.__class__
        if lext == Lop: return self.op_symb(lex)
        elif lext == Lexp: return self.exp_symb(lex)
        elif lext == Lloc: return Types.Loc('', int(lex, 16), True)
        raise Exception('Parsing error')

    def reduce_stack(self, stack, pre):
        """
        Compose instruction tuple
        :param stack: list of parsed instruction components
        :param pre: True if instruction has prefix operator
        """
        sl = len(stack)
        stack = stack[:1] + \
                (stack[::-1][1:-1] if isinstance(self, parseX86) else stack[1:-1]) + \
                stack[-1:] + [pre]
        if sl == 2: return Types.SingleInstr(stack)
        elif sl == 3: return Types.DoubleInstr(stack)
        elif sl == 4: return Types.TripleInstr(stack)
        elif sl == 5: return Types.FourInstr(stack)
        elif sl == 6: return Types.FiveInstr(stack)
        elif config.arch == config.ARCH_ARMT and sl == 8: return Types.CoproInstr(stack)
        raise Exception('Parsing error, strange number of tokens: ' + str(sl))

    def parse_instr(self, instr, loc):
        """
        Parse instruction
        :param instr: instruction string
        :param loc: virtual address string
        """
        self.call_des = False
        self.jmp_des = False
        self.indjmp_des = False
        has_pre = self.prefix_identify(instr)
        if has_pre: instr = prefix_sub(instr)
        lexem_list = lexer(instr, loc)
        s = map(self.push_stack, lexem_list)
        return self.reduce_stack(s, has_pre)
