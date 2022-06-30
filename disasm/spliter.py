"""
Divide data sections to assembler .byte declarations
"""

def dosplit(name):
    try:
        s = []
        f = open(name + '.info')
        for l in f:
            items = l.split()
            for item in items:
                for i in range(0, len(item), 2):
                    s.append('.byte 0x' + item[i:i+2])
        f.close()
    except: s = []
    with open(name + '_split.info', 'w') as f:
        f.write('\n'.join(reversed(s)))
        f.write('\n')


def main():
    dosplit('rodata')
    dosplit('data')
    dosplit('got')
    dosplit('eh_frame')
    dosplit('eh_frame_hdr')
