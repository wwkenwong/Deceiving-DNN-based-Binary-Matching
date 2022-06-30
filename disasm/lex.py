"""
Lexer
"""

import Types
import config
from utils.ail_utils import cat_from, split_by_list

class Lop(str): pass    # Operator lexeme
class Lexp(str): pass   # Expression lexeme
class Lloc(str): pass   # Virtual address lexeme

def check_assist(exp):
    """
    :param exp: expression string
    :return: True if assist operator
    """
    return exp in Types.AssistOp

def assist_exp(op, ass, exp, loc):
    """
    :param op: operator string
    :param ass: assist operator
    :param exp: operands string
    :param loc: virtual address
    :return: lexeme tuple
    """
    items = exp.split(',')
    return (Lop(op), Lexp(ass), Lexp(items[0]), Lloc(loc)) \
        if  len(items) == 1 \
        else (Lop(op), Lexp(ass), Lexp(items[0]), Lexp(items[1]), Lloc(loc))

def char_collect(s, f, c):
    """
    Find char from position
    :param s: haystack
    :param f: starting position
    :param c: needle
    :return: char index or None if not found
    """
    try: res = s[f:].index(c) + f
    except: res = None
    return res

def char_collect_all(s, c):
    """
    Find all appearances of char in string
    :param s: haystack
    :param c: needle
    :return: list of indices
    """
    start = 0
    res = []
    clen = len(c)
    while True:
        start = s.find(c, start)
        if start == -1: break
        res.append(start)
        start += clen
    return res

def bracket_collect(s):
    """
    Find opening and closing parenthesis
    :param s: haystack
    :return: zipper list of indices of opening and closing parenthesis
    """
    return zip(char_collect_all(s, '('),
               char_collect_all(s, ')'))

def comma_collect(s):
    """
    Find commas
    :param s: haystack
    :return: list of indices
    """
    return char_collect_all(s, ',')

if config.arch == config.ARCH_X86:
    def comma_in_brackets(e):
        """
        Find commas not inside brackets
        :param e: haystack
        :return: list of indices of commas outside brackets
        """
        clist = comma_collect(e)
        blist = bracket_collect(e)
        return filter(lambda com: not any(map(lambda br: br[0] < com < br[1], blist)), clist)
else:
    def comma_in_brackets(e):
        """
        Find commas not inside brackets
        :param e: haystack
        :return: list of indices of commas outside brackets
        """
        clist = comma_collect(e)
        blist = zip(char_collect_all(e, '{'), char_collect_all(e, '}')) if '{' in e \
                else zip(char_collect_all(e, '['), char_collect_all(e, ']'))
        return filter(lambda com: not any(map(lambda br: br[0] < com < br[1], blist)), clist)

def do_exp(e, op, l):
    """
    :param e: operands string
    :param op: opertor string
    :param l: virtual address
    :return: lexeme tuple
    :raise Exception: if bad instruction lenght
    """
    cl = comma_in_brackets(e)
    cl_len = len(cl)
    if cl_len == 0:
        return (Lop(op), Lexp(e), Lloc(l))
    elif cl_len < 4 or (config.arch == config.ARCH_ARMT and cl_len == 5):
        return (Lop(op),) + tuple(map(lambda e: Lexp(e.strip()), split_by_list(e, cl))) + (Lloc(l),)
    raise Exception("Unsupported exp length: " + str(cl_len))

def prefix_sub(instr):
    """
    Remove x86 instruction prefix
    :param instr: instruction string
    """
    return instr.replace('lock ', '') if 'lock ' in instr else instr

def lexer(instr, location):
    """
    Divide instruction into tokens
    :param instr: instruction string
    :param location: virtual address
    :return: lexeme tuple
    """
    instr = instr.strip()
    location = '0x' + location.strip()
    tokens = instr.split()
    op_str = tokens[0]
    if len(tokens) == 1:
        return (Lop(op_str), Lloc(location))
    elif check_assist(tokens[1]):
        return assist_exp(op_str, tokens[1], cat_from(tokens, 2, ' '), location)
    return do_exp(cat_from(tokens, 1, ' '), op_str, location)
