from utils.ail_utils import ELF_utils


def main():
    if ELF_utils.elf_32():
        lines = []
        with open('instrs.info') as f:
            lines = f.readlines()

        for i in range(len(lines)):
            l = lines[i]
            l = l.strip()
            if 'nop' in l:
                items = l.split()
                if 'nop' == items[-1]:
                    #l = l.split(':')[0] + " :"
                    l = l
            lines[i] = l+"\n"

        with open('instrs.info', 'w') as f:
            f.writelines(lines)
