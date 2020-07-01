import unicorn as uc
from unicorn.arm64_const import *
import sys
from elftools.elf import elffile
from binascii import *
import capstone as cs

u = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)

#loading ELF
fname = sys.argv[1]
print "loading %s" % fname
fd = open(fname, "rb")
elf = elffile.ELFFile(fd)
symbols = {}
for i in xrange(elf.num_sections()):
    section = elf.get_section(i)
    if section.header.sh_type in ['SHT_DYNSYM', "SHT_SYMTAB"]:
        for symbol in section.iter_symbols():
            if symbol.name != "" and "$" not in symbol.name:
                symbols[symbol.name] =  symbol.entry["st_value"]

for i in xrange(elf.num_segments()):
    segment = elf.get_segment(i)
    if segment.header["p_type"] == "PT_LOAD":
        def pagreesize(s):
            if s % 4096 == 0:
                return s
            return ((s / 4096) + 1) * 4096
        addr = segment.header["p_paddr"]
        size = pagreesize(segment.header["p_memsz"])
        data = segment.data()

        print("Loading 0x%x - 0x%x (%d bytes)" % (addr, addr+len(data), len(data)))
        u.mem_map(addr&0xffffffff000, size)
        u.mem_write(addr, data)

stack = 0xbabe0000
u.mem_map(stack, 1024)

src = 0xdead0000
u.mem_map(src, 1024)
u.mem_write(src, "A"*1024)

dst = 0xbeef0000
u.mem_map(dst, 1024)
u.mem_write(dst, "\x00"*1024)

u.reg_write(uc.arm64_const.UC_ARM64_REG_SP, stack+512)
u.reg_write(uc.arm64_const.UC_ARM64_REG_X0, dst+512+5)
u.reg_write(uc.arm64_const.UC_ARM64_REG_X1, src+512+5)
u.reg_write(uc.arm64_const.UC_ARM64_REG_X2, 0xfffffffffffffffe)

def hook_code(u, address, size, arg):
    c = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    instr = c.disasm( u.mem_read(address, size), size).next()
    print hex(address-symbols[sys.argv[2]]), instr.mnemonic, instr.op_str

    if instr.mnemonic[0] == "b":
        print " NZCV " + bin(u.reg_read(uc.arm64_const.UC_ARM64_REG_NZCV))

    if instr.mnemonic == "ret":
        data = u.mem_read(dst, 1024)
        for i in xrange(0, 1024, 32):
            print ("0x%04x  "%i) + hexlify(data[i:i+32])
        sys.exit(1)
        
u.hook_add(uc.UC_HOOK_CODE, hook_code, None)

u.emu_start(symbols[sys.argv[2]], 0)
print "Done"

