import struct
endianness = "<"

u32 = lambda x: struct.unpack(endianness+"L", x[:4])[0]

mkreg = lambda x: "R%d" % x

def decode_reglist(reg_list):
    regs = []
    for i in range(16):
        if reg_list & 0x1:
            regs.append(mkreg(i))
        reg_list = reg_list >> 1
    return regs

def bit(x, n):
    return (x & (1 << n)) >> n

def decode_blkxfer(inst):
    reglist = decode_reglist(inst & 0xffff)
    Rn = (inst & 0x000f0000) >> 16
    P  = bit(inst, 24)
    U  = bit(inst, 23)
    S  = bit(inst, 22)
    W  = bit(inst, 21)
    L  = bit(inst, 20)
    P = P and "B" or "A"
    U = U and "I" or "D"
    S = S and "U" or ""
    W = W and "!" or ""
    L = L and "LDM" or "STM"
    return (L+U+P+S, mkreg(Rn)+W, reglist)

def decode_branch(inst):
    link = bit(inst, 24)
    offset = (inst & 0x00ffffff)
    if offset & 0x00800000:
        offset -= 0x01000000
    offset = offset << 2
    if link:
        return ("BL", offset)
    return ("B", offset)

def decode_swi(inst):
    swi_nr = inst & 0x00ffffff
    return ("SWI", swi_nr)

def decode_stub(inst):
    #print hex(inst)
    return ("UNSUPPORTED", )

encs = {8 : decode_blkxfer,
        9 : decode_blkxfer,
        10 : decode_branch,
        11 : decode_branch,
        15 : decode_swi}

conds ={0:"EQ", 1:"NE", 2:"CS", 3:"CC",
        4:"MI", 5:"PL", 6:"VS", 7:"VC",
        8:"HI", 9:"LS", 10:"GE", 11:"LT",
        12:"GT", 13:"LE", 14:"AL", 15:"UD"}

def disassemble_instruction(inst):
    inst = u32(inst)
    cond = (inst & 0xf0000000) >> 28
    cond_ = conds.get(cond)
    inst_enc = (inst & 0x0f000000) >> 24
    inst_ = encs.get(inst_enc, decode_stub)(inst)
    return (cond_, )+inst_

def disassemble_all(data, addr=0):
    while data != "":
        yield (addr, disassemble_instruction(data[:4]))
        addr += 4
        data = data[4:]

if __name__ == "__main__":
    print disassemble_instruction("feffffea".decode("hex"))
    print disassemble_instruction("5555bde8".decode("hex"))
    print disassemble_instruction("0f802de9".decode("hex"))
    print disassemble_instruction("0f80bdd8".decode("hex"))
    print disassemble_instruction("414141ef".decode("hex"))
    print disassemble_instruction("ffffff1a".decode("hex"))
