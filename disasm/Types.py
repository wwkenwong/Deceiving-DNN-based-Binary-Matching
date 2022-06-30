"""
Types for code parsing
"""

import config

class RecSet(frozenset):
    """
    Set with recursive element search
    """

    def __init__(self, elems, final=False):
        self.final = final
        elems = map(lambda e: e.upper() if isinstance(e, str) else e, elems)
        super(RecSet, self).__init__(elems)

    def __new__(cls, elems, final=False):  # @UnusedVariable
        elems = map(lambda e: e.upper() if isinstance(e, str) else e, elems)
        return super(RecSet, cls).__new__(cls, elems)

    def __contains__(self, item):
        if isinstance(item, str): item = item.upper()
        if super(RecSet, self).__contains__(item):
            return True
        elif not self.final:
            return any(map(lambda e: isinstance(e, frozenset) and item in e, self))
        return False

class Container(object):
    """
    Simple container object
    """
    def __init__(self, content):
        self.content = content
    def __repr__(self):
        return repr(self.content)
    def __str__(self):
        return str(self.content)

class Func(object):
    """
    Function object
    """
    def __init__(self, name, begin, end, is_lib):
        self.func_name = name
        self.func_begin_addr = begin
        self.func_end_addr = end
        self.is_lib = is_lib
    def __contains__(self, addr):
        return self.func_begin_addr <= addr < self.func_end_addr
    def __repr__(self):
        return self.func_name + '@0x%X-0x%X' % (self.func_begin_addr, self.func_end_addr)

class Section(object):
    """
    Section object
    """
    def __init__(self, name, begin, size):
        self.sec_name = name
        self.sec_begin_addr = begin
        self.sec_size = size
    def __repr__(self):
        return 'section(' + self.sec_name + ':0x%X-0x%X)' % (self.sec_begin_addr, self.sec_begin_addr+self.sec_size)

class Loc(object):
    """
    Code location object
    """
    def __init__(self, label, addr, visible):
        self.loc_label = label
        self.loc_addr = addr
        self.loc_visible = visible
    def __repr__(self):
        return 'LOC:' + self.loc_label.replace('\n', ' ') + '@0x%X' % self.loc_addr

class Bblock(object):
    """
    Basic block object
    """
    def __init__(self, bf_name, bblock_name, bblock_begin_loc, bblock_end_loc, bblock_head_instr):
        self.bf_name = bf_name
        self.bblock_name = bblock_name
        self.bblock_begin_loc = bblock_begin_loc
        self.bblock_end_loc = bblock_end_loc
        self.bblock_head_instr = bblock_head_instr
    def __repr__(self):
        return 'BBLOC:' + self.bblock_name + '(' + str(self.bblock_begin_loc) + \
               ', ' + str(self.bblock_end_loc) + ')'

class control(object): pass
class J(control): pass
class F(control): pass

# Instruction classes
class Instr(tuple): pass
class SingleInstr(Instr):
    def __init__(self, items):
        if len(items) != 3: raise Exception('Invalid single')
        super(SingleInstr, self).__init__(items)
class DoubleInstr(Instr):
    def __init__(self, items):
        if len(items) != 4: raise Exception('Invalid double')
        super(DoubleInstr, self).__init__(items)
class TripleInstr(Instr):
    def __init__(self, items):
        if len(items) != 5: raise Exception('Invalid triple')
        super(TripleInstr, self).__init__(items)
class FourInstr(Instr):
    def __init__(self, items):
        if len(items) != 6: raise Exception('Invalid quad')
        super(FourInstr, self).__init__(items)
class FiveInstr(Instr):
    def __init__(self, items):
        if len(items) != 7: raise Exception('Invalid five')
        super(FiveInstr, self).__init__(items)

# Symbol and expressions
class Symbol(object): pass
class Exp(object): pass
class SegClass(str): pass
class Ptr(Exp): pass
class Label(str, Exp): pass

class JumpDes(int, Symbol): pass
class CallDes(Func, Symbol):
    def __init__(self, func):
        super(CallDes, self).__init__(func.func_name,
            func.func_begin_addr, func.func_end_addr, func.is_lib)
class StarDes(Exp, Symbol, Container): pass
class Const(long, Exp): pass
class Point(Const): pass
class Normal(Const): pass

class BinOP_Generic(tuple, Ptr):
    def __init__(self, items, preind=False):
        self.preind = preind
        super(BinOP_Generic, self).__init__(items)
    def __new__(cls, items, preind=False):  # @UnusedVariable
        return super(BinOP_Generic, cls).__new__(cls, items)
    def __repr__(self):
        return super(BinOP_Generic, self).__repr__() + ('!' if self.preind else '')
class BinOP_PLUS(BinOP_Generic): pass      # 0xABC(%esp),         [R1, #0x10]
class BinOP_PLUS_S(BinOP_Generic): pass    # S_0xABC(%esp)
class BinOP_MINUS(BinOP_Generic): pass     # -0xABC(%esp),        [R1, #-0x10]
class BinOP_MINUS_S(BinOP_Generic): pass   # -S_0xABC(%esp)
class ThreeOP(tuple, Ptr): pass            # (%edi, %esi, 8),     [R1, R2, LSL #1]
class FourOP_PLUS(tuple, Ptr): pass        # 0xABC(%esp,%eax,4)
class FourOP_MINUS(tuple, Ptr): pass       # -0xABC(%esp,%eax,4)
class FourOP_PLUS_S(tuple, Ptr): pass      # S_0xABC(%esp,%eax,4)
class FourOP_MINUS_S(tuple, Ptr): pass     # -S_0xABC(%esp,%eax,4)
class JmpTable_PLUS(tuple, Ptr): pass      # 0xABC(,%ebx,4)
class JmpTable_MINUS(tuple, Ptr): pass     # -0xABC(,%ebx,4)
class JmpTable_PLUS_S(tuple, Ptr): pass    # S_0xABC(,%ebx,4)
class JmpTable_MINUS_S(tuple, Ptr): pass   # -S_0xABC(,%ebx,4)
class SegRef(tuple, Ptr): pass             # %es:(%edi)
NegativePtr = (BinOP_MINUS, FourOP_MINUS, JmpTable_MINUS)
ErrorOp = RecSet(['(bad)'])

if config.arch == config.ARCH_X86:
    ###################################################
    ############## X86 DEFINITIONS ####################
    ###################################################

    CommonReg = RecSet([
        'RAX', 'RBX', 'RCX', 'RDX', 'RDI', 'RSI',
        'EAX', 'EBX', 'ECX', 'EDX', 'EDI', 'ESI',
        'AX', 'BX', 'CX', 'DX',
        'AL', 'BL', 'CL', 'DL',
        'AH', 'BH', 'CH', 'DH'
    ], True)
    SpecialReg = RecSet([
        'R8',  'R9',  'R10',  'R11',  'R12',  'R13',  'R14',  'R15',
        'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D',
        'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W',
        'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B',
        'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7'
        'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7'
    ], True)
    StackReg = RecSet(['RBP', 'RSP', 'ESP', 'EBP'], True)
    PCReg = RecSet(['EIP', 'RIP'], True)
    OtherReg = RecSet(['EIZ'], True)
    PtrType = RecSet(['QWORD', 'DWORD', 'WORD', 'TBYTE', 'BYTE'], True)
    MathOp = RecSet(['MATHADD'], True)
    Seg = RecSet(['FS', 'GS', 'CS', 'SS', 'DS', 'ES'], True)
    Reg = RecSet([CommonReg, SpecialReg, StackReg, PCReg, OtherReg])

    StackOp = RecSet(['PUSH', 'POP', 'PUSHL', 'POPL', 'PUSHF', 'POPF', 'PUSHFW', 'POPFW', 'PUSHFQ', 'POPFQ', 'PUSHQ', 'POPQ', 'PUSHW', 'POPW'], True)
    SystemOp = RecSet(['INT', 'IN', 'OUT', 'CPUID', 'SFENCE', 'PREFETCHNTA', 'PREFETCH', 'PREFETCHT0'], True)
    ArithmOp = RecSet(['ADC', 'ADD', 'XADD', 'SUB', 'ADDL', 'ADDQ', 'SUBL', 'SUBQ',
                       'MUL', 'IMUL', 'MULB', 'MULSD', 'DIV', 'IDIV', 'DIVL', 'ADCL',
                       'IDIVL', 'DIVSD', 'IVSS', 'MULSS', 'DIVQ', 'IDIVQ', 'PMULUDQ',
                       'INC', 'INCQ', 'INCL', 'INCW', 'DEC', 'NEG', 'SBB', 'FADD',
                       'NEGL', 'FMUL', 'FXCH', 'FUCOMIP', 'FUCOMI', 'FCOMPP',
                       'FCOMPL', 'BSR', 'MULL', 'FMULL', 'UCOMISD', 'UCOMISS', 'SUBSS',
                       'ADDW', 'ADDSD', 'ADDSS', 'FMULP', 'FMULS', 'FADDS', 'FADDP', 'FADDL',
                       'SUBW', 'SUBSD', 'IMULL', 'BSWAP', 'DECL', 'DECB', 'DECD', 'DECW',
                       'FDIV', 'FDIVL', 'ADDB', 'SUBB', 'SBBL', 'FDIVR', 'FABS', 'FSQRT',
                       'FDIVRS', 'CBTW', 'FRNDINT', 'FDIVRL', 'FPREM', 'CVTSI2SD',
                       'CVTSI2SDL', 'CVTSI2SSL', 'CVTSS2SD', 'CVTDQ2PS', 'CVTSI2SS',
                       'CVTTSD2SI', 'CVTTSS2SI', 'CVTSI2SDQ', 'CVTPS2PD',
                       'MAXSD', 'NEGQ', 'UNPCKLPS', 'UNPCKLPD', 'CVTPD2PS', 'CVTSD2SS',
                       'SQRTSS', 'MAXSS', 'MINSD', 'SQRTSD', 'MINSS', 'CVTTPS2DQ',
                       'DECQ', 'SUBPD', 'ADDPD', 'PADDQ', 'IMULQ', 'PADDD', 'PADDB',
                       'PSUBD', 'PSUBW', 'PSUBB', 'MULPD', 'UNPCKHPD', 'ADDPS', 'MULPS',
                       'DIVPD', 'DIVPS', 'CQTO', 'INCB', 'PSUBUSW', 'DIVSS', 'PUNPCKHBW',
                       'PUNPCKHWD', 'PUNPCKHDQ', 'PUNPCKHQDQ', 'PUNPCKLBW', 'PUNPCKLWD',
                       'PUNPCKLDQ', 'PUNPCKLQDQ', 'VDIVSD', 'VADDSD', 'VMULSD', 'VSHUFPS',
                       'VPADDD', 'VPSHUFB', 'VPSHUFD', 'VPSHUFHW', 'VPADDQ', 'VPALIGNR',
                       'DIVW', 'PMADDWD', 'PACKSSDW', 'PADDW', 'PACKUSWB', 'PMULHW',
                       'PFMUL', 'UNPCKHPS', 'PFADD', 'PMULLW', 'PACKSSWB', 'PMULHUW',
                       'PFSUB', 'PFSUBR', 'VPHADDD', 'PALIGNR', 'PHADDD', 'VPMULLD',
                       'PMULLD', 'VPABSD', 'VPMADDWD', 'VPMULDQ', 'VPSUBD', 'PABSD', 'PMULDQ',
                       'FYL2X', 'F2XM1', 'FSCALE', 'MAXPS', 'SQRTPS', 'VMULPS', 'VSQRTPS',
                       'VMAXPS', 'VADDPS', 'VSUBPS', 'ADCQ', 'FILDS'

    ], True)
    LogicOp = RecSet(['AND', 'ANDB', 'OR', 'XOR', 'PXOR', 'NOT', 'ANDL', 'NOTL', 'ORW',
                      'XORB', 'XORL', 'SAHF', 'ANDW', 'NOTB', 'NOTW', 'XORPD', 'XORPS',
                      'ANDQ', 'XORQ', 'ANDPS', 'ANDNPS', 'ORPS', 'ANDPD', 'NOTQ', 'ANDNPD',
                      'ORPD', 'PAND', 'POR', 'PANDN', 'VXORPD', 'VPXOR', 'BSF', 'POPCNT', 'TZCNT',
                      'VZEROUPPER', 'VXORPS', 'VANDPS'
    ], True)
    RolOp = RecSet(['ROL', 'SHL', 'SHR', 'SHLD', 'SHRD', 'SHRL', 'ROR', 'RORL',
                    'SAL', 'SAR', 'SHLL', 'ROLL', 'SHRB', 'SHLB', 'SARL', 'ROLW', 'SHLW',
                    'SARW', 'SHRW', 'SHLQ', 'SHRQ', 'PSHUFD', 'SHUFPS', 'SHUFPD',
                    'PSLLW', 'PSLLD', 'PSLLQ', 'PSRAW', 'PSRAD', 'PSLLDQ', 'PSRLDQ',
                    'PSRLD', 'PSHUFLW', 'SHRD', 'VPSLLD', 'VPSRLD', 'VPSLLDQ', 'VPSRLDQ',
                    'VPSRLQ', 'PSRLQ', 'PSRLW', 'SUBPS', 'VPSRAD', 'VPERMD', 'VPERMQ',
    ], True)
    AssignOp = RecSet(['MOV', 'XCHG', 'LEA', 'MOVSX', 'MOVSD', 'MOVL', 'FLDL', 'MOVZBL', 'MOVZBW',
                       'MOVSW', 'MOVAPD', 'MOVSLQ', 'MOVQ', 'MOVABS', 'MOVSBQ',
                       'MOVW', 'MOVZX', 'MOVAPS', 'FLD', 'FSTP', 'CMOVAE', 'CMOVE', 'CMOVNE', 'MOVSS',
                       'CMOVBE', 'CMOVB', 'CMOVS', 'CMOVA', 'CMOVNS', 'MOVB',
                       'MOVZWL', 'MOVSWL', 'MOVSBL', 'MOVSBW', 'FLDT', 'FSTPT', 'ORL', 'ORB', 'MOVSB',
                       'FNSTCW', 'FLDCW', 'FLDZ', 'REPZ', 'REPE', 'FSTPL', 'REPNZ',
                       'REP', 'FNSTSW', 'CMOVLE', 'CMOVG', 'CMOVL', 'FILDLL',
                       'FLDS', 'FILDL', 'FLD1', 'FDIVP', 'FSTL', 'FISTPL', 'FILD',
                       'FSUB', 'FDIVS', 'FISTPLL', 'FDIVRP', 'CMOVGE', 'FCMOVBE',
                       'FSUBP', 'FISTL', 'FSUBRP', 'FSUBRL', 'CWTL', 'FSUBRS', 'FSTPS',
                       'FSUBS', 'FSUBR', 'FSTS', 'FSUBL', 'FCMOVNBE', 'FCMOVE', 'FCMOVNE',
                       'FCMOVB', 'FISTP', 'FCMOVNB', 'CMOVNP', 'STOS', 'STOSB', 'STOSW', 'STOSD',
                       'FIST', 'FFREE', 'MOVSWQ', 'ORQ', 'MOVDQU', 'MOVDQA',
                       'MOVUPS', 'MOVD', 'MOVHLPS', 'MOVLHPS', 'MOVUPD', 'MOVNTI', 'MOVSL',
                       'PUNPCKHQDQ', 'PUNPCKLDQ', 'PUNPCKLBW', 'PINSRW', 'PEXTRW',
                       'PUNPCKLQDQ', 'PUNPCKLWD', 'MOVHPD', 'MOVLPD', 'LAHF', 'SAHF',
                       'RDTSC', 'VCVTSI2SD', 'VMOVDQU', 'VMOVDQA', 'VPBLENDW', 'VPUNPCKHQDQ',
                       'VPUNPCKHDQ', 'VPUNPCKLDQ', 'VPUNPCKLQDQ', 'VMOVUPS', 'VMOVAPS',
                       'MOVHPS', 'EMMS', 'PI2FD', 'FEMMS', 'CVTPS2PI', 'CVTPS2DQ', 'CVTPI2PS',
                       'MOVNTDQ', 'MOVZBQ', 'MOVZWQ', 'VMOVQ', 'VMOVD', 'CVTDQ2PD', 'VEXTRACTI128',
                       'VBROADCASTSS', 'XGETBV', 'VPBROADCASTD', 'VPMOVZXDQ', 'VPINSRQ', 'PMOVZXDQ',
                       'VINSERTI128', 'FLDLN2', 'FCMOVU', 'FLDL2E', 'FLDLG2', 'CVTSI2SSQ', 'VMOVSD',
                       'VMOVLHPS', 'VINSERTPS', 'FISTTPL', 'FISTTPLL', 'FISTTP', 'VMOVSS', 'VUNPCKLPS'
    ], True)
    CompareOp = RecSet(['CMP', 'CMPQ', 'TEST', 'CMPL', 'CMPB', 'CMPW', 'TESTB', 'TESTL', 'CMPSB',
                        'BT', 'TESTW', 'CMPNLESS', 'CMPLTSS', 'CMPNLTSS', 'TESTQ', 'CMPNLTSD',
                        'PCMPGTD', 'PCMPGTB', 'PCMPEQD', 'CMPLTSD', 'PCMPEQW', 'CMPEQSS', 'PCMPEQB',
                        'CMPLESD', 'CMPUNORDSS', 'CMPLESS', 'CMPNLESD', 'COMISD', 'COMISS', 'FCOMI',
                        'FCOMIP', 'FUCOMP', 'FUCOMPP', 'FUCOM'
    ], True)
    SetOp = RecSet(['SETA', 'SETAE', 'SETB', 'SETBE', 'SETC',
                    'SETNBE', 'SETNC', 'SETNG', 'SETNE',
                    'SETE', 'SETNP', 'SETGE', 'SETG', 'SETLE',
                    'SETL', 'SETP', 'SETNS', 'SETS'
    ], True)
    OtherOp = RecSet(['NOP', 'HLT', 'NOPW', 'NOPL', 'UD2'], True)
    JumpOp = RecSet(['JMP', 'JNE', 'JE', 'JB', 'JNAE', 'JNP',
                     'JC', 'JNB', 'JAE', 'JNC', 'JBE', 'JNA', 'JO',
                     'JA', 'JNBE', 'JL', 'JNGE', 'JGE', 'JNL', 'JLE',
                     'JNG', 'JG', 'JNLE', 'JS', 'JNS', 'JP', 'JMPQ'
    ], True)
    LoopOp = RecSet(['LOOP', 'LOOPE', 'LOOPNE'], True)
    FlagOp = RecSet(['CLD', 'CLTD', 'CLTQ'], True)
    AssistOp = RecSet(['SCAS', 'MOVSL', 'MOVSB', 'CMPSW', 'CMPSB', 'MOVSQ', 'POP', 'STOS'], True)
    ControlOp = RecSet([JumpOp, LoopOp, FlagOp,
                        'CALL', 'CALLQ',
                        'LEAVE', 'LEAVEQ',
                        'RET', 'RETN', 'RETQ',
                        'FXAM', 'FCHS'
    ])
    CommonOp = RecSet([ArithmOp, LogicOp, RolOp, AssignOp, CompareOp, SetOp, OtherOp])
    Op = RecSet([CommonOp, StackOp, ControlOp, SystemOp, ErrorOp])
    SuffixSize = {'Q': 8, 'L': 4, 'F': 4, 'W': 2}

elif config.arch == config.ARCH_ARMT:
    ###################################################
    ############## ARM DEFINITIONS ####################
    ###################################################

    CommonReg = RecSet(['R0',  'R1',  'R2',  'R3',  'R4',  'R5',  'R6',
                        'R7',  'R8',  'R9', 'R10', 'R11', 'R12'], True)
    SpecialReg = RecSet([ 'D0',  'D1',  'D2',  'D3',  'D4',  'D5',  'D6',  'D7',
                          'D8',  'D9', 'D10', 'D11', 'D12', 'D13', 'D14', 'D15',
                         'D16', 'D17', 'D18', 'D19', 'D20', 'D21', 'D22', 'D23',
                         'D24', 'D25', 'D26', 'D27', 'D28', 'D29', 'D30', 'D31',
                          'S0',  'S1',  'S2',  'S3',  'S4',  'S5',  'S6',  'S7',
                          'S8',  'S9', 'S10', 'S11', 'S12', 'S13', 'S14', 'S15',
                         'S16', 'S17', 'S18', 'S19', 'S20', 'S21', 'S22', 'S23',
                         'S24', 'S25', 'S26', 'S27', 'S28', 'S29', 'S30', 'S31',
                          'Q0',  'Q1',  'Q2',  'Q3',  'Q4',  'Q5',  'Q6',  'Q7',
                          'Q8',  'Q9', 'Q10', 'Q11', 'Q12', 'Q13', 'Q14', 'Q15',
                          'C0',  'C1',  'C2',  'C3',  'C4',  'C5',  'C6',  'C7',
                          'C8',  'C9', 'C10', 'C11', 'C12', 'C13', 'C14', 'C15'
    ], True)
    StackReg = RecSet(['R13', 'SP', 'FP', 'SB', 'SL'], True)
    LinkReg = RecSet(['R14', 'LR', 'IP'], True)
    PCReg = RecSet(['R15', 'PC'], True)
    Reg = RecSet([CommonReg, SpecialReg, StackReg, PCReg, LinkReg])

    StackOp = RecSet(['POP', 'PUSH', 'VPOP', 'VPUSH'], True)
    SystemOp = RecSet(['BKPT', 'CLREX', 'CPS', 'CPSIE', 'CPSID', 'DBG', 'DMB',
                       'DSB', 'ISB', 'PLD', 'PLI', 'RFE', 'SEV', 'SMC', 'SRS',
                       'SVC', 'WFE', 'WFI', 'YIELD', 'UDF'], True)
    ArithmOp = RecSet(['ADC', 'ADCS', 'ADD', 'ADDS', 'ADDW', 'ADR', 'AND', 'ANDS',
                       'CLZ', 'MLA', 'MLS', 'MUL', 'NEG', 'QADD', 'QADD16', 'QADD8',
                       'QASX', 'QDADD', 'QDSUB', 'QSAX', 'QSUB', 'QSUB16', 'QSUB8',
                       'RSB', 'RSBS', 'SADD16', 'SADD8', 'SASX', 'SBC', 'SBCS',
                       'SDIV', 'SHADD16', 'SHADD8', 'SHASX', 'SHSAX', 'SHSUB16',
                       'SHSUB8', 'SMLABB', 'SMLABT', 'SMLATB', 'SMLATT', 'SMLAD',
                       'SMLADX', 'SMLAL', 'SMLALBB', 'SMLALBT', 'SMLALTB', 'SMLALTT',
                       'SMLALD', 'SMLALDX', 'SMLAWB', 'SMLAWT', 'SMLSD', 'SMLSDX',
                       'SMLSLD', 'SMLSLDX', 'SMMLA', 'SMMLAR', 'SMMLS', 'SMMLSR',
                       'SMMUL', 'SMMULR', 'SMUAD', 'SMUADX', 'SMULBB', 'SMULBT',
                       'SMULTB', 'SMULTT', 'SMULL', 'SMULWB', 'SMULWT', 'SMUSD',
                       'SMUSDX', 'SSAT', 'SSAT16', 'SSAX', 'SSUB16', 'SSUB8',
                       'SUB', 'SUBS', 'SUBW', 'SXTAB', 'SXTAB16', 'SXTAH', 'SXTB',
                       'SXTB16', 'SXTH', 'UADD16', 'UADD8', 'UASX', 'UDIV', 'UHADD16',
                       'UHADD8', 'UHASX', 'UHSAX', 'UHSUB16', 'UHSUB8', 'UMAAL',
                       'UMLAL', 'UMULL', 'UQADD16', 'UQADD8', 'UQASX', 'UQSAX',
                       'UQSUB16', 'UQSUB8', 'USAD8', 'USADA8', 'USAT', 'USAT16',
                       'USAX', 'USUB16', 'USUB8', 'UXTAB', 'UXTAB16', 'UXTAH',
                       'UXTB', 'UXTB16', 'UXTH', 'VMUL', 'VNMUL', 'VMLA', 'VMLS',
                       'VNMLS', 'VNMLA', 'VADD', 'VSUB', 'VDIV', 'VABS', 'VNEG',
                       'VSQRT', 'VRHADD', 'VADDL', 'VRADDHN', 'VMAX'
    ], True)
    LogicOp = RecSet(['BIC', 'BICS', 'EOR', 'EORS', 'ORN', 'ORNS', 'ORR', 'ORRS',
                      'PKHBT', 'PKHTB', 'RBIT', 'REV', 'REV16', 'REVSH', 'SBFX',
                      'UBFX'], True)
    RolOp = RecSet(['ASR', 'ASRS', 'LSL', 'LSLS', 'LSR', 'LSRS', 'ROR', 'RORS',
                    'RRX', 'RRXS'], True)
    AssignOp = RecSet(['BFC', 'BFI', 'CPY', 'LDM', 'STM', 'LDMDB', 'LDMEA', 'LDMIA', 'LDMFD',
                       'LDR', 'LDRB', 'LDRBT', 'LDRD', 'LDREX', 'LDREXB', 'LDREXD',
                       'LDREXH', 'LDRH', 'LDRHT', 'LDRSB', 'LDRSBT', 'LDRSH', 'LDRSHT',
                       'LDRT', 'MOV', 'MOVS', 'MOVW', 'MOVT', 'MRS', 'MSR', 'MVN', 'MVNS',
                       'SEL', 'STMDB', 'STMFD', 'STMIA', 'STMEA', 'STR', 'STRB', 'STRBT',
                       'STRD', 'STREX', 'STREXB', 'STREXD', 'STREXH', 'STRH', 'STRHT',
                       'STRT', 'VCVT', 'VCVTT', 'VCVTR', 'VCVTB', 'VMOV', 'VMSR',
                       'VSTR', 'VSTM', 'VSTMDB', 'VPUSH', 'VLDR', 'VLDM', 'VLDMDB',
                       'VLD4', 'VSTMIA', 'VLDMIA', 'VMRS', 'VLDMDB'
    ], True)
    CompareOp = RecSet(['CMN', 'CMP', 'IT', 'TEQ', 'TST', 'VCMP', 'VCMPE', 'ITE', 'ITT',
                        'ITTT', 'ITTE', 'ITEE', 'ITET', 'ITTTT', 'ITTTE', 'ITTET', 'ITTEE',
                        'ITETT', 'ITETE', 'ITEET', 'ITEEE'], True)
    OtherOp = RecSet(['CDP', 'CDP2', 'LDC', 'LDCL', 'LDC2', 'LDC2L', 'MCR', 'MCR2',
                      'MCRR', 'MCRR2', 'MRC', 'MRC2', 'MRRC', 'MRRC2', 'NOP', 'SETEND',
                      'STC', 'STC2', 'STCL', 'STC2L'], True)
    AssistOp = RecSet([], True)
    ControlOp = RecSet(['B', 'BL', 'BLX', 'BX', 'BXJ', 'CBNZ', 'CBZ', 'TBB', 'TBH'], True)
    CondSuff = RecSet(['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'LO',
                       'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'HS'], True)
    OpQualifier = RecSet(['W', 'N', 'F32', 'F64', 'U8', 'U16', 'U32', 'S8', 'S16', 'S32', 'I16', '8'])
    CommonOp = RecSet([ArithmOp, LogicOp, RolOp, AssignOp, CompareOp])
    Op = RecSet([CommonOp, StackOp, ControlOp, SystemOp, OtherOp])
    DataTypes = RecSet(['.word', '.short', '.byte'], True)

    class RegList(tuple): pass
    class InlineData(str): pass
    class ShiftExp(Exp):
        def __init__(self, op, val):
            self.op = op; self.val = val
        def __repr__(self):
            return self.op + ' #' + str(self.val)
    class TBExp(Exp):
        def __init__(self, base, dest):
            self.base = base; self.dest = dest
        def __repr__(self):
            return '(' + self.dest + '-' + self.base + ')/2'
    class CoproInstr(Instr):
        def __init__(self, items):
            if len(items) != 9: raise Exception('Invalid copro: %d fields' % len(items))
            super(CoproInstr, self).__init__(items)


class RegClass(str, Exp):
    def __init__(self, reg):
        if reg not in Reg: raise Exception('Not a register: ' + reg)
        super(RegClass, self).__init__(reg)
class IncReg(RegClass):
    def __init__(self, reg):
        super(IncReg, self).__init__(reg[:-1])
    def __new__(cls, reg):
        if reg[-1] != '!': raise Exception('Invalid IncReg')
        return super(IncReg, cls).__new__(cls, reg[:-1])
    def __str__(self):
        return super(IncReg, self).__str__() + '!'
class AssistOpClass(str, Exp):
    def __init__(self, op):
        if op not in AssistOp: raise Exception('No assist op: ' + op)
        super(AssistOpClass, self).__init__(op)

class UnOP(RegClass, Ptr): pass       # (%ebx), [r1]

