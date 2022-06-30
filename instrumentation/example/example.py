from disasm import Types
from utils.ail_utils import ELF_utils

def perform(instrs, funcs):
    # Do stuff to the instruction list
    if not ELF_utils.elf_arm():
        instrs.append(Types.TripleInstr(('mov', Types.RegClass('eax'), Types.RegClass('eax'), Types.Loc('', 0, True), False)))
    return instrs


def aftercompile():
    # Do stuff to source file after compilation
    pass
