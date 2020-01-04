from __future__ import print_function
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

import os
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm import *
import time
import math

## step3 实现功能
## 实现最简单的JNI调用，newStringUtf, 结果在JavaVM中存储
##函数返回值为JavaVm中的索引(非地址),索引与真实值的映射关系由Java层维护

md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    CODE = uc.mem_read(address, size)
    # print("r0=%x, r1=%x, r2=%x, r3=%x, sp=%x, pc=%x" % (
    #     mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1), mu.reg_read(UC_ARM_REG_R2),
    #     mu.reg_read(UC_ARM_REG_R3), mu.reg_read(UC_ARM_REG_SP), mu.reg_read(UC_ARM_REG_PC)))
    # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x,code=%s" % (
    #     address, size, ''.join(format(x, '02x') for x in CODE)))
    value = mu.reg_read(UC_ARM_REG_CPSR) & 1
    if (value == 1):
        for i in md_thumb.disasm(CODE, address):
            print("%x:\t%s\t%s\t%s" % (i.address, ''.join(format(x, '02x') for x in CODE), i.mnemonic, i.op_str))
    else:
        for i in md_arm.disasm(CODE, address):
            print("%x:\t%s\t%s\t%s" % (i.address, ''.join(format(x, '02x') for x in CODE), i.mnemonic, i.op_str))

    if mu.mem_read(address, size) == b"\xE8\xBF":
        print("new string_utf:%s", uc.mem_read(mu.reg_read(UC_ARM_REG_R1), 10))
        mu.reg_write(UC_ARM_REG_R0, 0x23)
        # print(uc.mem_read(mu.reg_read(UC_ARM_REG_R0), 10))


OVERRIDE_TIMEOFDAY = False
OVERRIDE_TIMEOFDAY_SEC = 0
OVERRIDE_TIMEOFDAY_USEC = 0

OVERRIDE_CLOCK = False
OVERRIDE_CLOCK_TIME = 0


def _handle_gettimeofday(uc, tv, tz):
    """
    If either tv or tz is NULL, the corresponding structure is not set or returned.
    """
    if tv != 0:
        if OVERRIDE_TIMEOFDAY:
            uc.mem_write(tv + 0, int(OVERRIDE_TIMEOFDAY_SEC).to_bytes(4, byteorder='little'))
            uc.mem_write(tv + 4, int(OVERRIDE_TIMEOFDAY_USEC).to_bytes(4, byteorder='little'))
        else:
            timestamp = time.time()
            (usec, sec) = math.modf(timestamp)
            usec = abs(int(usec * 100000))

            uc.mem_write(tv + 0, int(sec).to_bytes(4, byteorder='little'))
            uc.mem_write(tv + 4, int(usec).to_bytes(4, byteorder='little'))

    if tz != 0:
        uc.mem_write(tz + 0, int(-120).to_bytes(4, byteorder='little'))  # minuteswest -(+GMT_HOURS) * 60
        uc.mem_write(tz + 4, int().to_bytes(4, byteorder='little'))  # dsttime

    return 0


# callback for tracing instructions
def hook_interrupt(uc, intno, data):
    idx = mu.reg_read(UC_ARM_REG_R7)
    if (idx != 0x4E):
        print("Unhandled interrupt %d at %x, stopping emulation" % (intno, mu.reg_read(UC_ARM_REG_PC)))
        mu.emu_stop()
    else:
        print("handle interrupt gettimeofday")
        args = [mu.reg_read(reg_idx) for reg_idx in range(UC_ARM_REG_R0, UC_ARM_REG_R6 + 1)]
        result = _handle_gettimeofday(uc, args[0], args[1])
        mu.reg_write(UC_ARM_REG_R0, result)


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

ARM_CODE = bytes(read_into_buffer("libnative-lib.so_0xb3ae3000_0x6000.so.2"))
ADDRESS = 0xb3ae3000
print("Emulate arm code")

LIB_C_CODE = bytes(read_into_buffer("libc.so_0xb6c23000_0x79000.so"))
LIB_C_ADDRESS = 0xb6c23000


def addJniMap(mu, base):
    mu.mem_map(base, 0x6000)
    addr_func = base + 0x2000
    offset = 0x29c
    mu.mem_write(base + offset, b"\x89\x49\x00\x00")  # b"\x01\x12\x03\x05"
    asm = "PUSH {R4,LR}\n" \
          "MOV R4, #" + hex(offset) + "\n" \
                                      "IT AL\n" \
                                      "POP {R4,PC}"
    keystone = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    asm_bytes_list, asm_count = keystone.asm(bytes(asm, encoding='ascii'))
    mu.mem_write(0x4988, bytes(asm_bytes_list))

    mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x4988, end=0x4998)
    pass


try:
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(ADDRESS, 0x6000)
    mu.mem_write(ADDRESS, ARM_CODE)

    mu.mem_map(LIB_C_ADDRESS, 0x79000)
    mu.mem_write(LIB_C_ADDRESS, LIB_C_CODE)

    mu.reg_write(UC_ARM_REG_R0, 0xfffe09a0)
    mu.reg_write(UC_ARM_REG_R1, 0x75a7134a)
    mu.reg_write(UC_ARM_REG_R2, 0x0)
    mu.reg_write(UC_ARM_REG_R3, 0x4)

    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)

    mu.mem_map(0xb6c9c000, 0x9000)
    mu.mem_map(0xfffe0000, 0x1000)
    addJniMap(mu, 0x0)

    mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=2 * 1024 * 1024)
    mu.hook_add(UC_HOOK_INTR, hook_interrupt)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    stop_pos = 0xb6ca2ffe
    mu.reg_write(UC_ARM_REG_LR, stop_pos)
    mu.emu_start(ADDRESS + 0xf31, 0xb6ca2ffe)

    print("Emulation done. Below is the CPU context")
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    print(">>> R0 = 0x%x" % r0)
    print(">>> R1 = 0x%x" % r1)
    print(">>> R2 = 0x%x" % r2)
    print("ts= %ld" % (r0 + (r1 << 32)))
except UcError as e:
    print("ERROR: %s" % e)

# CODE = b"\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
