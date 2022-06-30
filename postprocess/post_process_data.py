from utils.ail_utils import *

unit_data_size = 1


def main():
    global unit_data_size
    if ELF_utils.elf_32():
        unit_data_size = 4
    elif ELF_utils.elf_64():
        unit_data_size = 8

    if ELF_utils.elf_exe():
        lines = []
        with open("final_data.s", 'r') as f:
            lines = f.readlines()

            in_rodata = False
            in_data = False
            in_bss = False

            for i in range(len(lines)):
                if in_data is False and ".data" in lines[i]:
                    in_data = True
                    # do not occupy exist data, but insert new lines
                    if config.diversification_mode == 3:
                        lines[i] += 'global_des: ' + '.byte 0x00\n' * unit_data_size
                        lines[i] += 'branch_des: ' + '.byte 0x00\n' * unit_data_size
                    elif config.diversification_mode == 5:
                        lines[i] += 'global_des: ' + '.byte 0x00\n' * unit_data_size
                    lines[i] += 'tmp_value1: ' + '.byte 0x00\n' * unit_data_size
                    lines[i] += 'tmp_value2: ' + '.byte 0x00\n' * unit_data_size
                    lines[i] += 'tmp_value3: ' + '.byte 0x00\n' * unit_data_size
                    lines[i] += 'tmp_value4: ' + '.byte 0x00\n' * unit_data_size
                elif in_rodata is False and '.rodata' in lines[i]:
                    in_rodata = True
                elif in_bss is False and '.bss' in lines[i]:
                    in_bss = True
                    break

        with open('final_data.s', 'w') as f:
            f.writelines(lines)
