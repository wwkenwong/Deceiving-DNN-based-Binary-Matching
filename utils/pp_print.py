"""
Pretty print to string
"""

from disasm import Types
from utils.ail_utils import ELF_utils, get_loc


def p_op(op):
    """
    String from operator
    :param op: operator
    :return: lowercase operator
    """
    return str(op).lower()

def p_seg(seg):
    """
    String of segment
    :param seg: segment
    :return: lowercase %segment
    """
    return '%' + str(seg).lower()

def p_assist(assist):
    """
    String of assist operator
    :param assist: assist operator
    :return: lowercase assist operator
    """
    return str(assist).lower()

def p_loc(loc):
    """
    String of location address
    :param loc: location address
    :return: lowercase hexdecimal string
    """
    return '0x%x' % loc

if ELF_utils.elf_arm():
    ## ARM

    def p_reg(reg):
        """
        String of register
        :param reg: register
        :return: lowercase register string
        """
        return str(reg).lower()

    def p_shift(shift):
        """
        String of shift operand
        :param shift: shift value
        :return: shift operand string
        """
        return shift.op + ' #' + str(shift.val)

    def p_tbexp(tbe):
        """
        String of inline jump table element
        :param tbe: jump table element
        """
        return tbe.__repr__()

    def p_ptraddr(addr):
        """
        String of indirect addressing
        :param addr: indirect addressing
        :return: indirect addressing string
        """
        if isinstance(addr, Types.UnOP):
            return '[' + p_reg(addr) + ']'
        elif isinstance(addr, Types.BinOP_PLUS):
            return '[' + p_reg(addr[0]) + (',#0x%x' % addr[1]) + (']!' if addr.preind else ']')
        elif isinstance(addr, Types.BinOP_PLUS_S):
            return '[' + p_reg(addr[0]) + ',' + addr[1] + (']!' if addr.preind else ']')
        elif isinstance(addr, Types.BinOP_MINUS):
            return '[' + p_reg(addr[0]) + (',#-0x%x' % addr[1]) + (']!' if addr.preind else ']')
        elif isinstance(addr, Types.BinOP_MINUS_S):
            return '[' + p_reg(addr[0]) + ',-' + addr[1] + (']!' if addr.preind else ']')
        elif isinstance(addr, Types.ThreeOP):
            return '[' + p_reg(addr[0]) + ',' + p_reg(addr[1]) + \
                   (',' + p_shift(addr[2]) if addr[2].val > 0 else '') + ']'

    def p_const(const):
        """
        String of constant
        :param const: constant
        :return: constant string
        """
        return ('#' if isinstance(const, Types.Normal) else '') + ('-' if const < 0 else '') + '0x%X' % abs(const)

    def p_symbol(sym):
        """
        String of branch destination symbol
        :param sym: branch destination symbol
        """
        if isinstance(sym, Types.CallDes): return sym.func_name
        elif isinstance(sym, Types.JumpDes): return p_loc(sym)
        elif isinstance(sym, Types.StarDes): return p_reg(sym.content)

    def p_reglist(exp):
        """
        String of register list
        :param exp: register list
        """
        return '{' + ','.join(exp) + '}'

    def p_triple(p, e1, e2):
        """
        String of triple instruction
        :param p: operator
        :param e1: first operand
        :param e2: second operand
        :return: instruction string
        """
        p_str = p_op(p)
        e1_str = p_exp(e1)
        e2_str = p_exp(e2)
        return p_str + ' ' + e1_str + ',' + e2_str

    def p_four(p, e1, e2, e3):
        """
        String of quad instruction
        :param p: operator
        :param e1: first operand
        :param e2: second operand
        :param: e3: third operand
        :return: instruction string
        """
        p_str = p_op(p)
        e1_str = p_exp(e1)
        e2_str = p_exp(e2)
        e3_str = p_exp(e3)
        return p_str + ' ' + e1_str + ',' + e2_str + ',' + e3_str

    def p_five(p, e1, e2, e3, e4):
        """
        String of five element instruction
        :param p: operator
        :param e1: first operand
        :param e2: second operand
        :param: e3: third operand
        :param: e4: fourth operand
        :return: instruction string
        """
        p_str = p_op(p)
        e1_str = p_exp(e1)
        e2_str = p_exp(e2)
        e3_str = p_exp(e3)
        e4_str = p_exp(e4)
        return p_str + ' ' + e1_str + ',' + e2_str + ',' + e3_str + ',' + e4_str

    def p_copro(i):
        """
        String of ARM coprocessor instruction
        :param i: instruction
        :return: instruction string
        """
        p_str = p_op(i[0])
        return p_str + ' ' + ','.join(map(p_exp, i[1:7]))

else:
    ## X86

    def p_reg(reg):
        """
        String of register
        :param reg: register
        :return: lowercase register string
        """
        return '%' + str(reg).lower()

    def p_ptraddr(addr):
        """
        String of indirect addressing
        :param addr: indirect addressing
        :return: indirect addressing string
        """
        if isinstance(addr, Types.UnOP):
            return '(' + p_reg(addr) + ')'
        elif isinstance(addr, Types.BinOP_PLUS):
            return p_loc(addr[1]) + '(' + p_reg(addr[0]) + ')'
        elif isinstance(addr, Types.BinOP_PLUS_S):
            return addr[1] + '(' + p_reg(addr[0]) + ')'
        elif isinstance(addr, Types.BinOP_MINUS):
            return '-' + p_loc(addr[1]) + '(' + p_reg(addr[0]) + ')'
        elif isinstance(addr, Types.BinOP_MINUS_S):
            return '-' + addr[1] + '(' + p_reg(addr[0]) + ')'
        elif isinstance(addr, Types.ThreeOP):
            return '(' + p_reg(addr[0]) + ',' + p_reg(addr[1]) + ',' + p_loc(addr[2]) + ')'
        elif isinstance(addr, Types.FourOP_PLUS):
            return p_loc(addr[3]) + '(' + p_reg(addr[0]) + ',' + p_reg(addr[1]) + ',' + str(addr[2]) + ')'
        elif isinstance(addr, Types.FourOP_MINUS):
            return '-' + p_loc(addr[3]) + '(' + p_reg(addr[0]) + ',' + p_reg(addr[1]) + ',' + str(addr[2]) + ')'
        elif isinstance(addr, Types.FourOP_PLUS_S):
            return addr[3] + '(' + p_reg(addr[0]) + ',' + p_reg(addr[1]) + ',' + str(addr[2]) + ')'
        elif isinstance(addr, Types.FourOP_MINUS_S):
            return '-' + addr[3] + '(' + p_reg(addr[0]) + ',' + p_reg(addr[1]) + ',' + str(addr[2]) + ')'
        elif isinstance(addr, Types.JmpTable_PLUS):
            return p_loc(addr[0]) + '(,' + p_reg(addr[1]) + ',' + p_loc(addr[2]) + ')'
        elif isinstance(addr, Types.JmpTable_MINUS):
            return '-' + p_loc(addr[0]) + '(,' + p_reg(addr[1]) + ',' + p_loc(addr[2]) + ')'
        elif isinstance(addr, Types.JmpTable_PLUS_S):
            return addr[0] + '(,' + p_reg(addr[1]) + ',' + p_loc(addr[2]) + ')'
        elif isinstance(addr, Types.JmpTable_MINUS_S):
            return '-' + addr[0] + '(,' + p_reg(addr[1]) + ',' + p_loc(addr[2]) + ')'
        elif isinstance(addr, Types.SegRef):
            return p_seg(addr[0]) + ':' + p_exp(addr[1])

    def p_const(const):
        """
        String of constant
        :param const: constant
        :return: constant string
        """
        sign = '-' if const < 0 else ''
        if isinstance(const, Types.Normal): return '$' + sign + '0x%X' % abs(const)
        elif isinstance(const, Types.Point): return sign + '0x%X' % abs(const)

    def p_symbol(sym):
        """
        String of branch destination symbol
        :param sym: branch destination symbol
        """
        if isinstance(sym, Types.CallDes): return sym.func_name
        elif isinstance(sym, Types.JumpDes): return p_loc(sym)
        elif isinstance(sym, Types.StarDes): return '*' + p_exp(sym.content)

    def p_triple(p, e1, e2):
        """
        String of triple instruction
        :param p: operator
        :param e1: first operand
        :param e2: second operand
        :return: instruction string
        """
        p_str = p_op(p)
        e1_str = p_exp(e1)
        e2_str = p_exp(e2)
        if e2_str.lower() == 'pop':
            return p_str + ' ' + e2_str + ' ' + e1_str
        return p_str + ' ' + e2_str + ',' + e1_str

    def p_four(p, e1, e2, e3):
        """
        String of quad instruction
        :param p: operator
        :param e1: first operand
        :param e2: second operand
        :param: e3: third operand
        :return: instruction string
        """
        p_str = p_op(p)
        e1_str = p_exp(e1)
        e2_str = p_exp(e2)
        e3_str = p_exp(e3)
        if e3_str in Types.AssistOp:
            return p_str + ' ' + e3_str + ' ' + e2_str + ',' + e1_str
        return p_str + ' ' + e3_str + ',' + e2_str + ',' + e1_str

    def p_five(p, e1, e2, e3, e4):
        """
        String of five element instruction
        :param p: operator
        :param e1: first operand
        :param e2: second operand
        :param: e3: third operand
        :param: e4: fourth operand
        :return: instruction string
        """
        p_str = p_op(p)
        e1_str = p_exp(e1)
        e2_str = p_exp(e2)
        e3_str = p_exp(e3)
        e4_str = p_exp(e4)
        return p_str + ' ' + e4_str + ',' + e3_str + ',' + e2_str + ',' + e1_str


def p_exp(exp):
    """
    String from expression
    :param exp: expression
    :return: expression string
    """
    if isinstance(exp, Types.Const): return p_const(exp)
    elif isinstance(exp, Types.Symbol): return p_symbol(exp)
    elif isinstance(exp, Types.AssistOpClass): return p_assist(exp)
    elif isinstance(exp, Types.Ptr): return p_ptraddr(exp)
    elif isinstance(exp, Types.RegClass): return p_reg(exp)
    elif isinstance(exp, Types.Label): return str(exp)
    elif ELF_utils.elf_arm():
        if isinstance(exp, Types.ShiftExp): return p_shift(exp)
        elif isinstance(exp, Types.RegList): return p_reglist(exp)
        elif isinstance(exp, Types.TBExp): return p_tbexp(exp)

def p_single(p):
    """
    String of single instruction
    :param p: operator
    :return: instruction string
    """
    return p_op(p)

def p_double(p, e):
    """
    String of double instruction
    :param p: operator
    :param e: first operand
    :return: instruction string
    """
    assert p_op(p) is not None, 'operator is None'
    assert p_exp(e) is not None, 'operand is None, operator is %s' % p_op(p)
    return p_op(p) + ' ' + p_exp(e)

def p_location(loc):
    """
    Get location label
    :param loc: location object
    :return: label string
    """
    return loc.loc_label

def p_prefix(pre):
    """
    Get instruction prefix string
    :param pre: True if prefix present
    :return: prefix string
    """
    return ' lock ' if pre else ''

def pp_print_instr(i):
    """
    Get instruction string in assembler syntax
    :param i: instruction
    :return: instruction string
    """
    loc = get_loc(i)
    if not loc.loc_visible: return p_location(loc)
    res = p_location(loc) + p_prefix(i[-1])
    if isinstance(i, Types.SingleInstr):
        res += p_single(i[0])
    elif isinstance(i, Types.DoubleInstr):
        res += p_double(i[0], i[1])
    elif isinstance(i, Types.TripleInstr):
        res += p_triple(i[0], i[1], i[2])
    elif isinstance(i, Types.FourInstr):
        res += p_four(i[0], i[1], i[2], i[3])
    elif isinstance(i, Types.FiveInstr):
        res += p_five(i[0], i[1], i[2], i[3], i[4])
    elif ELF_utils.elf_arm() and isinstance(i, Types.CoproInstr):
        res += p_copro(i)
    return res

def pp_print_list(ilist):
    """
    Instruction list to string list
    :param ilist: instruction list
    :return: list of assembler strings
    """
    return map(pp_print_instr, ilist)

def pp_print_file(ilist):
    """
    Write instruction string list to file
    :param ilist: string list
    """
    with open('final.s', 'w') as f:
        f.write('.section .text\n')
        if ELF_utils.elf_arm(): f.write('.syntax unified\n.align 2\n.thumb\n')
        f.write('\n'.join(ilist))
        f.write('\n\n')

def pp_print_hex(h):
    """
    Byte string to hex
    :param h: list of bytes
    :return: list of hex strings
    """
    return map(lambda e: hex(ord(e)), h)
