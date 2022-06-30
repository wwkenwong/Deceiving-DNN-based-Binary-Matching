import os
import re
import shutil
import config


def func_addr(filename, count, fexclude=''):
    """
    Dump function symbols and addresses
    :param filename: path to target executable
    :param count: unused
    :param fexclude: path to file of function symbols to exclude from dump
    """

    os.system(config.objdump + ' -Dr -j .text ' + filename + ' > dump.s')
    os.system('grep ">:" dump.s > fl')

    if len(fexclude) > 0 and os.path.isfile(fexclude):
        os.system('grep -v -f ' + fexclude + ' fl > fl.filtered')
        shutil.move('fl.filtered', 'fl')

    with open('fl') as f: fnl = f.readlines()

    fnl_old = []
    if os.path.isfile('faddr_old.txt'):
        with open('faddr_old.txt') as f:
            fnl_old = f.readlines()

    fnl_old = map(lambda l : int(l.split()[0], 16), fnl_old)
    #fnl_old = map(lambda l : l.split()[0], fnl_old)
    #print fnl_old

    blacklist = ['__libc_csu_init', '__libc_csu_fini', '__i686.get_pc_thunk.bx', '__do_global_ctors_aux', '_start', '__do_global_dtors_aux', 'frame_dummy']
    addrs = []
    addrs_2 = []
    regex = re.compile(r'S_(0x[0-9A-F]{7})', re.I)
    regex1 = re.compile(r'<(.*)>:', re.I)

    for fn in fnl:
        # ad-hoc solution, we don't consider basic block labels as functions
        if not "BB_" in fn:
            if "S_" in fn:
                m = regex.search(fn)
                if m:
                    d = m.groups()[0]
                    d1 = int(d,16)
                    if d1 in fnl_old:
                        addr = fn.split('<')[0].strip()
                        addrs.append("0x" + addr + '\n')
                        addrs_2.append(fn)
            elif count > 0:
                m = regex1.search(fn)
                if m:
                    d = m.groups()[0]
                    if not d in blacklist:
                        addr = fn.split('<')[0].strip()
                        addrs.append("0x" + addr + '\n')
                        addrs_2.append(fn)
            else:
                addr = fn.split('<')[0].strip()
                addrs.append("0x" + addr + '\n')
                addrs_2.append(fn)

    with open('faddr.txt', 'w') as f:
        f.writelines(addrs)

    with open('faddr_old.txt', 'w') as f:
        f.writelines(addrs_2)

    shutil.copy('faddr.txt', 'faddr.txt.' + str(count))
    shutil.copy('faddr_old.txt', 'faddr_old.txt.' + str(count))



def useless_func_discover(filename):

    black_list = ('_start', '__do_global_dtors_aux', 'frame_dummy', '__do_global_ctors_aux', '__i686.get_pc_thunk.bx', '__libc_csu_fini', '__libc_csu_init')

    os.system(config.objdump + ' -Dr -j .text ' + filename + ' > ' + filename + '.temp')

    with open(filename + '.temp') as f:
        lines = f.readlines()

    lines.append('')
    start_addr = 0
    end_addr = 0
    in_func = 'NULL'
    last_addr = 0

    def check (l):
        for b in black_list:
            if '<'+b+'>:' in l: return b
        return 'NULL'

    res = {}
    for l in lines:
        if l.strip() == "":
            if in_func != "NULL":
                end_addr = last_addr
                if end_addr[-1] == ':':
                    end_addr = end_addr[:-1]
                res[in_func] = (start_addr, end_addr)
                in_func = "NULL"
        else:
            if check (l) != "NULL":
                in_func = check(l)
                start_addr = l.split()[0]
                last_addr = start_addr
            else:
                last_addr = l.split()[0]

    res_list = []
    for key, value in res.items():
        res_list.append(key + " " + value[0] + " " + value[1] +'\n')

    with open("useless_func.info", 'w') as f:
        f.writelines(res_list)

