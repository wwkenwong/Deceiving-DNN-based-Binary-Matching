"""
Assembler code for gfree key generation and failure routine
"""

import config
from utils.ail_utils import ELF_utils


keygenfunction = ''
keysize = 'long'
failfunction = ''

if ELF_utils.elf_64():
    # x86_64
    keysize = 'quad'
    keygenfunction = '''
pushq %rax
pushq %rbx
pushq %rcx
pushq %rdx
pushq %rsi
pushq %rdi
xorl %esi,%esi
movl $.LC2,%edi
xorl %eax,%eax
call open
testl %eax,%eax
js {0}
movl $8,%edx
movl ${1},%esi
movl %eax,%edi
movl %edi,%ebx
call read
cmpq $8,%rax
jne {0}
movl $8,%edx
movl ${2},%esi
movl %ebx,%edi
call read
cmpq $8,%rax
jne {0}
movl %ebx,%edi
call close
movb $1,{3}
popq %rdi
popq %rsi
popq %rdx
popq %rcx
popq %rbx
popq %rax
'''

    failfunction = '''{0}: movq stderr(%rip),%rcx
cmpb $0,{1}
jne .{0}.L1
movl $.LC1,%edi
movl $49,%edx
jmp .{0}.L2
.{0}.L1: movl $.LC0,%edi
movl $18,%edx
.{0}.L2: movl $1,%esi
call fwrite
movl $-1,%edi
call exit


'''

elif ELF_utils.elf_arm():
    # ARM
    keygenfunction = '''
push {{r0,r1,r2,r4,r12,lr}}
movw r0,#:lower16:.LC2
movt r0,#:upper16:.LC2
movs r1,#0
bl open
subs r4,r0,#0
blt {0}
movs r2,#4
movw r1,#:lower16:{1}
movt r1,#:upper16:{1}
bl read
cmp r0,#4
mov r2,r0
bne {0}
movw r1,#:lower16:{2}
movt r1,#:upper16:{2}
mov r0,r4
bl read
cmp r0,#4
bne {0}
mov r0,r4
bl close
movw r1,#:lower16:{3}
movt r1,#:upper16:{3}
movs r0,#1
str r0, [r1]
pop {{r0,r1,r2,r4,r12,lr}}
'''

    failfunction = '''.thumb_func
{0}: movw r3,#:lower16:stderr
movt r3,#:upper16:stderr
ldr r3,[r3]
movw r0,#:lower16:{1}
movt r0,#:upper16:{1}
ldr r0, [r0]
cbnz r0, .{0}.L1
movs r2,#49
movw r0,#:lower16:.LC1
movt r0,#:upper16:.LC1
b .{0}.L2
.{0}.L1: movs r2,#18
movw r0,#:lower16:.LC0
movt r0,#:upper16:.LC0
.{0}.L2: movs r1,#1
bl fwrite
mov r0,#-1
bl exit


'''

else:
    # x86_32
    keygenfunction = '''
pushl %eax
pushl %ebx
pushl %ecx
pushl %edx
subl $16,%esp
pushl $0
pushl $.LC2
call open
addl $16, %esp
testl %eax, %eax
js {0}
subl $4, %esp
pushl $4
pushl ${1}
pushl %eax
call read
popl %ebx
addl $12, %esp
cmpl $4, %eax
jne {0}
subl $4, %esp
pushl $4
pushl ${2}
pushl %ebx
call read
addl $16, %esp
cmpl $4, %eax
jne {0}
subl $12, %esp
pushl %ebx
call close
movb $1,{3}
addl $24, %esp
popl %edx
popl %ecx
popl %ebx
popl %eax
'''

    failfunction = '''{0}: pushl stderr
cmpb $0,{1}
jne .{0}.L1
pushl $49
pushl $1
pushl $.LC1
jmp .{0}.L2
.{0}.L1: pushl $18
pushl $1
pushl $.LC0
.{0}.L2: call fwrite
movl $-1,(%esp)
call exit


'''


beforemain = keygenfunction.format(config.gfree_failfuncname, config.gfree_xorkeyvar,
                                       config.gfree_cookiekeyvar, config.gfree_keygenflagvar)
aftercode = failfunction.format(config.gfree_failfuncname, config.gfree_keygenflagvar)
instrdata = '''
.section .rodata
.LC0: .string "Fatal GFree Error\\n"
.LC1: .string "GFree Error: not enough entropy to generate keys\\n"
.LC2: .string "/dev/urandom"
{6}
.section .bss
{1}: .{0} 0
{2}: .{0} 0
{7}: .byte 0

.global {3}
.section .tbss,"awT",{5}nobits
.type {3}, {5}object
.size {3}, 0x{4:x}
{3}: .zero 0x{4:x}
'''.format(keysize, config.gfree_xorkeyvar, config.gfree_cookiekeyvar,
           config.gfree_cookiestackvar, config.gfree_cookiestacksize * 1024,
           '%' if ELF_utils.elf_arm() else '@',
           ('.LC3: .word ' + config.gfree_cookiestackvar + '(tpoff)\n') if ELF_utils.elf_arm() else '',
           config.gfree_keygenflagvar)
