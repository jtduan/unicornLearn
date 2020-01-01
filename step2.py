from __future__ import print_function

import os
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm import *

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    CODE = uc.mem_read(address, size)
    print("r0=%x, r1=%x, r2=%x, r3=%x, sp=%x" % (
        mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1), mu.reg_read(UC_ARM_REG_R2),
        mu.reg_read(UC_ARM_REG_R3), mu.reg_read(UC_ARM_REG_SP)))

    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x,code=%s" % (
        address, size, ''.join(format(x, '02x') for x in CODE)))
    for i in md.disasm(CODE, address):
        print("%x:\t%s\t%s\t%s" % (i.address, ''.join(format(x, '02x') for x in CODE), i.mnemonic, i.op_str))

    if (address == 0xb3b64e54):
        print(uc.mem_read(mu.reg_read(UC_ARM_REG_R2), 4))


# callback for tracing instructions
def hook_interrupt(uc, intno, data):
    print("Unhandled interrupt %d at %x, stopping emulation" % (intno, mu.reg_read(UC_ARM_REG_PC)))
    mu.emu_stop()


# callback for tracing instructions
# Todo:可能是参数搞错了，第3个参数是地址
def hook_unmapped(uc, address, size, value, user_data, extra):
    print("unmapped: 0x%x" % (size))


# 把文件内容以byte字节形式读写到缓冲区中。
def read_into_buffer(filename):
    buf = bytearray(os.path.getsize(filename))
    with open(filename, 'rb') as f:
        f.readinto(buf)
    f.close()
    return buf


STACK_ADDR = 0xc0000000
STACK_SIZE = 1024 * 1024

ARM_CODE = bytes(read_into_buffer("libnative-lib.so_0xb3b64000_0x6000.so"))
ADDRESS = 0xb3b64000
print("Emulate arm code")
try:
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    mu.mem_write(ADDRESS, ARM_CODE)
    mu.reg_write(UC_ARM_REG_R0, 0xfffe09a0)
    mu.reg_write(UC_ARM_REG_R1, 0x75a7134a)
    mu.reg_write(UC_ARM_REG_R2, 0x0)
    mu.reg_write(UC_ARM_REG_R3, 0x4)

    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)

    mu.mem_map(0xb6d30000, 0x80000)
    # mu.mem_write(0xb6d30ec0, b'\x00\x00')

    mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=2 * 1024 * 1024)
    mu.hook_add(UC_HOOK_INTR, hook_interrupt)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    stop_pos = 0xb6dafff0
    mu.reg_write(UC_ARM_REG_LR, stop_pos)
    mu.emu_start(ADDRESS + 0xe49, 0xb6dafff0)

    print("Emulation done. Below is the CPU context")
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    print(">>> ECX = 0x%x" % r0)
    print(">>> EDX = 0x%x" % r1)
    print(">>> EDX = 0x%x" % r2)
except UcError as e:
    print("ERROR: %s" % e)

# CODE = b"\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
