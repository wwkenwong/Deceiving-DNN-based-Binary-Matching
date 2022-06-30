"""
Selects export data from export table and dump their memory addresses
"""


def main():
    with open('export_tbl.info') as f:
        lines = f.readlines()

    datas = []
    for l in lines:
        items = l.split()
        if "OBJECT" in items and '@' not in items:
            v = int(items[1], 16)
            if v != 0:
                addr = "0x" + items[1] + '\n'
                datas.append(addr)

    with open('export_datas.info', 'w') as f:
        f.writelines(datas)

    return datas