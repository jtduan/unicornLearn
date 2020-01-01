from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm import *

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    CODE = uc.mem_read(address, size)
    for i in md.disasm(CODE, address):
        print("%x:\t%s\t%s\t%s" % (i.address, ''.join(format(x, '02x') for x in CODE), i.mnemonic, i.op_str))


ARM_CODE = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"
THUMB_CODE = "\x83\xb0"
ADDRESS = 0x1000000
print("Emulate arm code")
try:
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    mu.mem_write(ADDRESS, ARM_CODE)
    mu.reg_write(UC_ARM_REG_R0, 0x1234)
    mu.reg_write(UC_ARM_REG_R1, 0x6789)
    mu.reg_write(UC_ARM_REG_R2, 0x3333)
    mu.reg_write(UC_ARM_REG_R3, 0x1111)
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=2 * 1024 * 1024)
    mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))
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
