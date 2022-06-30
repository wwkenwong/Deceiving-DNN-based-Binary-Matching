"""
Generic utilities
"""

import re
import time
from operator import itemgetter

import config
from disasm import Types


def unify_int_list(intlist):
    """
    Remove duplicates and sort list of integers
    :param intlist: list of integers
    :return: sorted unique list
    """
    return sorted(set(intlist))

def unify_str_list(strlist):
    """
    Remove duplicates and sort list of strings
    :param strlist: list of strings
    :return: sorted unique list
    """
    return sorted(set(strlist))

def unify_funclist_by_name(funclist):
    """
    Remove duplicates by name from a list of function objects
    :param funclist: list of function objects
    :return: list of function objects with unique names
    """
    return {f.func_name: f for f in funclist}.values()

def unify_funclist_by_addr(funclist):
    """
    Remove duplicates by address from a sorted list of function objects
    :param funclist: list of function objects
    :return: list of function objects with unique address
    """
    res = []
    for i in range(len(funclist)-1):
        h1 = funclist[i]
        h2 = funclist[i+1]
        if h1.func_begin_addr == h2.func_begin_addr:
            if 'S_0x' in h2.func_name: funclist[i+1] = h1
            else: res.append(h1)
        else: res.append(h1)
    res.append(funclist[-1])
    return res

def merge_intervals(intervals):
    """
    Merge overlapping items in a list of intervals
    :param interval: list of tuples representing intervals
    :return: list of non-overlapping intervals
    """
    res = []
    if not intervals: return []
    sorted_intervals = sorted(intervals, key=itemgetter(0))
    low, high = sorted_intervals[0]
    for iv in sorted_intervals[1:]:
        if iv[0] <= high:
            high = max(high, iv[1])
        else:
            res.append((low, high))
            low, high = iv
    res.append((low, high))
    return res

def get_loc(instr):
    """
    Retrieve location from instruction
    Note: The return value has side effect
    :param instr: instruction tuple
    :return: location of the instruction
    """
    return instr[-2]

def set_loc(instr, loc):
    """
    Set new location in an instruction
    :param instr: target instruction
    :param loc: location object to be set
    :return: instruction with updated location
    """
    t = type(instr)
    l = len(instr)
    return t(instr[:l-2] + (loc,) + instr[-1:])


def get_op(instr):
    """
    Retrieve operation from the instruction
    :param instr: instruction tuple
    :return: operation of the instruction
    """
    return instr[0]


def get_cf_des(instr):
    """
    Retrieve the destination of DoubleInstr
    :param instr: a DoubleInstr
    :return: the destination of the instruction or None
    """
    if isinstance(instr, Types.DoubleInstr):
        return instr[1]
    else:
        return None

def get_addr(instr):
    """
    Get location address from instruction
    :param instr: instruction tuple
    :return: address of the instruction
    """
    return get_loc(instr).loc_addr

def get_label(instr):
    """
    Get location label from instruction
    :param instr: instruction tuple
    :return: label of the instruction
    """
    return get_loc(instr).loc_label

def update_label(instr, label):
    """
    Set new label in an instruction
    :param instr: instruction tuple
    :param label: label to be set
    :return: instruction with updated label
    """
    loc = get_loc(instr)
    loc.loc_label = label
    return set_loc(instr, loc)

def increase_ptr(instr, pos, gap):
    """
    Increase indirect addressing offset in an instruction
    :param instr: instruction tuple
    :param pos: position of the indirect addressing in the instruction tuple
    :param gap: value to be added to the offset
    :return: instruction with updated addressing
    """
    ptr = instr[pos]
    offset = ptr[-1] + (-gap if isinstance(ptr, Types.NegativePtr) else gap)
    ptr = type(ptr)(ptr[:-1] + (offset,))
    return type(instr)(instr[:pos] + (ptr,) + instr[pos+1:])

def read_file(filename):
    """
    Read whole file to list of stripped strings
    :param filename: filepath
    :return: list of strings
    """
    with open(filename) as f:
        lines = f.readlines()
    return map(str.rstrip, lines)

def dec_hex(val):
    """
    Format inteegr to hex
    :param val: integer value
    :return: string of hexadecimal representation
    """
    return '0x%X' % val

def print_loclist(loclist):
    """
    Print list of location objects
    :param loclist: list of locations
    """
    for loc in loclist:
        print loc.loc_label
        print dec_hex(loc.loc_addr)

def print_addrlist(intlist):
    """
    Print list of integer addresses as hex
    :param intlist: list of integers
    """
    print '\n'.join(map(dec_hex, intlist))

def cat_from(strlist, v, suf):
    """
    Concatenate sublist of strings
    :param strlist: list of strings
    :param v: sublist starting position
    :param suf: glue string
    :return: concatenated string
    """
    # return ''.join(map(lambda s: s + suf, strlist[v:]))
    return suf.join(strlist[v:])

def split_by_list(s, intlist):
    """
    Split iterable by a list of indices
    :param s: iterable
    :param intlist: list of indices
    :return: list of splitted parts
    """
    res = []
    points = [0] + intlist + [len(s)]
    for i in range(len(points)-1):
        res.append(s[points[i]:points[i+1]])
        points[i+1] += 1
    return res

def int_of_string_opt(s, base=10):
    """
    Convert string to integer without raising exceptions
    :param s: integer string
    :param base: numbering base
    :return: integer value or None on failure
    """
    try: return int(s, base)
    except: return None

def print_exp_type(exp):
    """
    Print type of expression
    :param exp: expression
    """
    if isinstance(exp, Types.Const): print 'const'
    elif isinstance(exp, Types.Symbol): print 'symbol'
    elif isinstance(exp, Types.RegClass): print 'reg'
    elif isinstance(exp, Types.AssistOpClass): print 'assist'
    elif isinstance(exp, Types.Ptr): print 'ptr'
    elif isinstance(exp, Types.Label): print 'label'

def print_instr_type(instr):
    """
    Print type of instruction
    :param instr: instruction tuple
    """
    print instr.__class__.__name__

def sort_loc(loclist):
    """
    Sort list of location objects by address
    :param loclist: list of locations
    :return: sorted list of locations
    """
    return sorted(loclist, cmp=lambda l1,l2: l1.loc_addr - l2.loc_addr)

def get_instr_byloc(instrlist, loclist):
    """
    Filter sorted instruction list by a sorted list of locations
    :param instrlist: sorted instruction list
    :param loclist: sorted location list
    :return: list of matching instrctions
    """
    res = []
    i = 0; j = 0
    while j < len(loclist):
        iloc = get_loc(instrlist[i])
        if iloc.loc_addr == loclist[j].loc_addr:
            res.append(instrlist[i])
            j += 1
        i += 1
    return res

def recover_addr_from_label(lab):
    """
    Get address from generated label (e.g. S_0x400400)
    :param lab: label string
    :return: integer address
    """
    try: return int(lab.strip()[2:], 16)
    except: return -1

def get_next_bb(sn):
    """
    Increment BB_ label numbering
    :param sn: BB label string
    :return: incremented label string
    """
    assert('BB_' in sn)
    return 'BB_' + str(int(sn.strip()[3:]) + 1)

def memo(f):
    """
    Generate function with result memory
    :param f: basic function
    :return: function with result memory
    """
    m = {}
    def func(x):
        if x in m: return m[x]
        m[x] = f(x)
        return m[x]
    return func

def bbn_byloc(e, ls):
    """
    Binary search value in list of integers
    :param e: needle
    :param ls: haystack
    :return: True if found, False otherwise
    """
    def bs(low, up):
        if low > up: return False
        mid = (low + up) >> 1
        if e == ls[mid]: return True
        elif e < ls[mid]: return bs(low, mid-1)
        return bs(mid+1, up)
    return bs(0, len(ls) - 1)


class ELF_utils(object):
    """
    Utilities for targeted ELF file info
    """

    @staticmethod
    def elf_check(key):
        """
        Find keyword in unix file description
        :param key: keyword string
        :return: True if found
        """
        with open('elf.info') as f:
            line = f.readline()
        return key in line

    @staticmethod
    def elf_32():
        """
        :return: True if analyzing 32bit binary
        """
        return config.is_32

    @staticmethod
    def elf_64():
        """
        :return: True if analyzing 64bit binary
        """
        return not config.is_32

    @staticmethod
    def elf_dynamic():
        """
        :return: True if binary is dynamically linked
        """
        return config.is_dynamic

    @staticmethod
    def elf_static():
        """
        :return: True if binary is statically linked
        """
        return not config.is_dynamic

    @staticmethod
    def elf_unstrip():
        """
        :return: True if binary is not stripped
        """
        return ELF_utils.elf_check('not stripped')

    @staticmethod
    def elf_strip():
        """
        :return: True if binary is stripped
        """
        return not ELF_utils.elf_unstrip()

    @staticmethod
    def elf_lib():
        """
        :return: True if binary is a shared library
        """
        return config.is_lib

    @staticmethod
    def elf_exe():
        """
        :return: True if binary is executable
        """
        return not config.is_lib

    @staticmethod
    def elf_arm():
        """
        :return: True if binary is compiled for ARM Thumb
        """
        return config.arch == config.ARCH_ARMT


class Opcode_utils(object):
    """
    Utilities for instruction analysis
    """

    if config.arch == config.ARCH_ARMT:
        # ARM specific definitions

        # Pattern for function call operator
        call_patt = re.compile('^blx?([a-z]{2})?$', re.I)

        # Pattern for indirect branch operator
        indjmp_patt = re.compile('^bl?x([a-z]{2})?$', re.I)

        @staticmethod
        def is_cp(op):
            """
            :param op: operator string
            :return: True if control flow operator
            """
            parts = op.split('.')
            return parts[0] in Types.ControlOp or (parts[0][-2:] in Types.CondSuff and parts[0][:-2] in Types.ControlOp)

        simplejumps = set(['B', 'BX'])
        @staticmethod
        def is_jmp(op):
            """
            :param op: operator string
            :return: True if unconditional jump
            """
            return op.split('.')[0].upper() in Opcode_utils.simplejumps

        @staticmethod
        def is_cond_jmp(op):
            """
            :param op: operator string
            :return: True if conditional jump
            """
            parts = op.split('.')
            return parts[0][-2:] in Types.CondSuff \
                and parts[0][:-2] in Types.ControlOp \
                and not parts[0][:-2].upper().startswith('BL')

        simplemovs = set(['MOV', 'MOVS', 'MOVW', 'MOVT'])
        @staticmethod
        def is_mov(op):
            """
            :param op: operator string
            :return: True if move operator
            """
            return op.split('.')[0].upper() in Opcode_utils.simplemovs

        @staticmethod
        def is_call(op):
            """
            :param op: operator string
            :return: True if function calling operator
            """
            return Opcode_utils.call_patt.match(op) is not None

        @staticmethod
        def is_ret(instr):
            """
            :param instr: instruction tuple
            :return: True if function return operation
            """
            op, exp1, exp2 = instr[:3]
            if op.upper().startswith('POP') and isinstance(exp1, Types.RegList):
                return 'PC' in map(str.upper, exp1)
            elif op.upper().startswith('LDR') and isinstance(exp2, Types.Ptr) \
                and ('sp' in exp2 or 'SP' in exp2):
                return exp1.upper() == 'PC'
            elif Opcode_utils.is_cp(op) and isinstance(exp1, Types.RegClass):
                return exp1.upper() == 'LR'
            return False

        @staticmethod
        def is_cmp_op(op):
            """
            :param op: operator string
            :return: True if comparison operator
            """
            return op.split('.')[0] in Types.CompareOp

        @staticmethod
        def is_assign(op):
            """
            :param op: operator string
            :return: True if assignment operator
            """
            return op.split('.')[0] in Types.AssignOp

    else:
        # x86 specific definitions

        # Pattern for function call operator
        call_patt = re.compile('^callq?$', re.I)

        @staticmethod
        def is_cp(op):
            """
            :param op: operator string
            :return: True if control flow operator
            """
            return op in Types.JumpOp or op.upper().startswith('CALL')

        simplejumps = set(['JMP', 'JMPQ'])
        @staticmethod
        def is_jmp(op):
            """
            :param op: operator string
            :return: True if unconditional jump
            """
            return op.upper() in Opcode_utils.simplejumps

        @staticmethod
        def is_cond_jmp(op):
            """
            :param op: operator string
            :return: True if conditional jump
            """
            return not Opcode_utils.is_jmp(op) and op in Types.JumpOp

        simplemovs = set(['MOV', 'MOVL'])
        @staticmethod
        def is_mov(op):
            """
            :param op: operator string
            :return: True if move operator
            """
            return op.upper() in Opcode_utils.simplemovs

        @staticmethod
        def is_call(op):
            """
            :param op: operator string
            :return: True if function calling operator
            """
            return op.upper().startswith('CALL')

        retstatements = set(['RET', 'RETN', 'RETQ'])
        @staticmethod
        def is_ret(instr):
            """
            :param instr: instruction tuple
            :return: True if function return operation
            """
            op = instr[0].upper()
            exp1 = instr[1]
            return op in Opcode_utils.retstatements or \
                   op == 'REPZ' and isinstance(exp1, str) and exp1.upper() in Opcode_utils.retstatements

        @staticmethod
        def is_cmp_op(op):
            """
            :param op: operator string
            :return: True if comparison operator
            """
            return op in Types.CompareOp

        @staticmethod
        def is_assign(op):
            """
            :param op: operator string
            :return: True if assignment operator
            """
            return op in Types.AssignOp

    @staticmethod
    def is_control_des(i):
        """
        :param i: instruction tuple
        :return: True if branch destination
        """
        return ':' in get_label(i)

    @staticmethod
    def is_func(e):
        """
        :param e: expression
        :return: True if function call destination
        """
        return isinstance(e, Types.CallDes)

    @staticmethod
    def is_mem_exp(e):
        """
        :param e: expression
        :return: True if indirect addressing expression
        """
        if isinstance(e, Types.StarDes):
            return Opcode_utils.is_mem_exp(e.content)
        return isinstance(e, Types.Ptr)

    @staticmethod
    def is_push(op):
        """
        :param op: operator
        :return: True if push operator
        """
        return op.upper().startswith('PUSH')

    @staticmethod
    def is_pop(op):
        """
        :param op: operator
        :return: True if pop operator
        """
        return op.upper().startswith('POP')

    @staticmethod
    def is_subtraction(op):
        """
        :param op: operator
        :return: True if subtraction operator
        """
        return op.upper().startswith('REPLACE')

    @staticmethod
    def is_stack_op(op):
        """
        :param op: operator
        :return: True if stack operator
        """
        return op in Types.StackOp

    @staticmethod
    def is_indirect(s):
        """
        :param s: symbol
        :return: True if indirect branch operand
        """
        return isinstance(s, Types.StarDes)

    @staticmethod
    def is_any_jump(op):
        """
        :param op: operator
        :return: True if jump operator
        """
        return Opcode_utils.is_jmp(op) or Opcode_utils.is_cond_jmp(op)

    @staticmethod
    def is_control_transfer_op(op, exp1):
        """
        :param op: operator
        :param exp1: first operand
        :return: True if control transfer operator
        """
        return Opcode_utils.is_call(op) \
               or Opcode_utils.is_jmp(op) \
               or Opcode_utils.is_cond_jmp(op) \
               or Opcode_utils.is_ret((op, exp1))


class Exp_utils(object):
    """
    Utilities for expression analysis
    """

    @staticmethod
    def is_reg(e):
        """
        :param e: expression
        :return: True if register
        """
        return isinstance(e, Types.RegClass)

    @staticmethod
    def is_const(e):
        """
        :param e: expression
        :return: True if constant
        """
        return isinstance(e, Types.Const)

    @staticmethod
    def is_mem(e):
        """
        :param e: expression
        :return: True if indirect addressing
        """
        return isinstance(e, Types.Ptr)


class Time_Record(object):
    """
    Time utilities
    """

    @staticmethod
    def stamp():
        """
        Print seconds from epoc
        """
        print 'stamp : %f sec' % time.time()

    @staticmethod
    def get_utime():
        """
        :return: floating point seconds from epoc
        """
        return time.time()

    @staticmethod
    def elapsed(t):
        """
        Print elapsed time
        :param t: start instant
        """
        print 'execution elapsed time: %f sec' % (time.time() - t)
