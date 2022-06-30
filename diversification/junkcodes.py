from disasm.Types import *
from utils.ail_utils import *
from utils.pp_print import *
from copy import deepcopy
import random
from config import junk_code_level


class JunkBase:

    def __init__(self):
        pass

    def get_codes(self):
        return []

class Junk4(JunkBase):
    def __init__(self, iloc):
        JunkBase.__init__(self)
        self._loc = deepcopy(iloc)
        self._loc.loc_label = ''
        self._regs1 = RegClass(random.choice(['EAX', 'EBX']))
        self._regs2 = RegClass(random.choice(['ECX', 'EDX']))
        # https://c9x.me/x86/html/file_module_x86_id_34.html
        mov_inst = ['cmove', 'cmovns', 'cmovbe', 'cmovnbe', 
                    'cmovpo', 'cmovnb', 'cmovnl', 'cmovg', 
                    'cmovge', 'cmovl', 'cmovno', 'cmovz', 
                    'cmovpe', 'cmovne', 'cmovle', 'cmovnge', 
                    'cmovp', 'cmovs', 'cmovnle', 'cmovc', 
                    'cmovna', 'cmovnc', 'cmovo', 'cmova', 
                    'cmovnae', 'cmovae', 'cmovnz', 'cmovng', 
                    'cmovnp', 'cmovb']
        self._mov = random.choice(mov_inst)

    def get_codes(self):
        # mov dest, src

        # mov tmp_value1, register 
        # mov register ,0x13371337
        # mov register,tmp_value1
        return [
            TripleInstr(('mov', Label('tmp_value2'), self._regs2,  self._loc, None)),
            TripleInstr(('mov', Label('tmp_value1'), self._regs1,  self._loc, None)),
            TripleInstr((self._mov, self._regs1, self._regs2,  self._loc, None)),
            TripleInstr(('mov', self._regs2, Normal(0x42424242),  self._loc, None)),
            TripleInstr(('mov', Label('tmp_value4'), self._regs1,  self._loc, None)),

            TripleInstr(('mov', self._regs1, Normal(0x13371337), self._loc, None)),
            TripleInstr(('mov', self._regs2, Label('tmp_value2'), self._loc, None)),
            TripleInstr(('mov', self._regs1, Label('tmp_value4'), self._loc, None)),
        ]


class Junk3(JunkBase):
    def __init__(self, iloc):
        JunkBase.__init__(self)
        self._loc = deepcopy(iloc)
        self._loc.loc_label = ''
        self._regs1 = RegClass(random.choice(['EAX', 'EBX']))
        self._regs2 = RegClass(random.choice(['ECX', 'EDX']))

    def get_codes(self):
        return [
            TripleInstr(('xchg', self._regs1, Label('tmp_value1'), self._loc, None)),
            TripleInstr(('xchg', self._regs2, Label('tmp_value1'), self._loc, None)),
            TripleInstr(('xchg', self._regs1, self._regs2, self._loc, None)),
            TripleInstr(('xchg', self._regs2, Label('tmp_value1'), self._loc, None)),
        ]

class Junk1(JunkBase):

    def __init__(self, iloc):
        JunkBase.__init__(self)
        self._loc = deepcopy(iloc)
        self._loc.loc_label = ''
        self._regs1 = RegClass('EBP')
        self._regs2 = RegClass('ESP')

    def get_codes(self):
        return [
            TripleInstr(('xchg', self._regs1, self._regs2, self._loc, None)),
            TripleInstr(('xchg', self._regs1, self._regs2, self._loc, None))
        ]

class Junk0(JunkBase):
    def __init__(self, iloc):
        pass

    def get_codes(self):
        return []


class Junk2(JunkBase):

    def __init__(self, iloc):
        JunkBase.__init__(self)
        self._loc = deepcopy(iloc)
        self._loc.loc_label = ''
        self._regs1 = RegClass(random.choice(['EAX', 'EBX', 'ECX', 'EDX', 'EBP', 'ESP']))

    def get_codes(self):
        return [
            TripleInstr(('xchg', self._regs1, Label('tmp_value1'), self._loc, None)),
            TripleInstr(('xchg', self._regs1, Label('tmp_value1'), self._loc, None))
        ]


junk_codes = [
    Junk0,
    Junk1,
    Junk2,
    Junk3,
    Junk4,
    Junk4,
    Junk4,
]


def get_junk_codes(loc, level=None):
    if level is None:
        if junk_code_level is None:
            level = random.randint(1, len(junk_codes)-1)
        else:
            level = junk_code_level
    junk_class = junk_codes[level]
    junk_instance = junk_class(loc)
    return junk_instance.get_codes()
