import shutil
import os.path


def do_check (addr, info_range):
    addrn = int(addr, 16)
    for ran in info_range:
        ba = int(ran[0], 16)
        ea = int(ran[1], 16)
        #if addrn >= ran[0] and addrn <= ran[1]:
        if addrn >= ba and addrn <= ea:
            #print addr + " in " + ran[0] + " " + ran[1]
            return True
    return False


def check (l, info_range):
    l = l.strip()
    if l == "": return False
    if ">:" in l: return False
    addr = l.split(':')[0]
    return do_check(addr, info_range)


def main(filepath):

    if not os.path.isfile('useless_func.info'):
        # this is the first round
        shutil.copy(filepath + '.temp', filepath + '.disassemble')
        return

    with open(filepath + '.temp') as f:
        lines = f.readlines()

    with open('useless_func.info') as f:
        infos = f.readlines()

    info_range = []
    for info in infos:
        items = info.split()
        #ba = int(items[1], 16)
        #ea = int(items[2], 16)
        #info_range.append((ba,ea))
        info_range.append((items[1],items[2]))

    #print info_range
    print "0: useless libc functions removing"

    for i in range(6,len(lines)):
        l = lines[i]
        if check (l, info_range): lines[i] = ""

    with open(filepath + '.disassemble', 'w') as f:
        f.writelines(lines)

    #lines = []
    #with open('count.txt') as f:
    #    lines = f.readlines()
    #c = lines[0].strip()
    #os.system("cp " + fn + ".disassemble " + fn + ".disassemble."+c)
