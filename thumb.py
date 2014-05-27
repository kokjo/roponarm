import struct
endianness = "<"

u32 = lambda x: struct.unpack(endianness+"L", x[:4])[0]
u16 = lambda x: struct.unpack(endianness+"H", x[:2])[0]

mkreg = lambda x: "R%d" % x

def bit(x, n):
    return (x & (1 << n)) >> n

def decode_reglist(reg_list):
    regs = []
    for i in range(8):
        if reg_list & 0x1:
            regs.append(mkreg(i))
        reg_list = reg_list >> 1
    return regs

def decode_push_pop(inst):
    if bit(inst, 10) != 1 or bit(inst, 9) != 0:
        return ("UNSUPPORTED", )
    L = bit(inst, 11)
    R = bit(inst, 8)
    reglist = decode_reglist(inst & 0xff)
    if R:
        reglist.append(mkreg(15))
    L = L and "POP" or "PUSH"
    return (L, reglist)

def decode_alu_imm(inst):
    op = (inst & 0x1800) >> 11
    Rd = (inst & 0x0700) >> 8
    off = inst & 0x00ff
    op = ["MOV", "CMP", "ADD", "SUB"][op]
    return (op, mkreg(Rd), off)


def decode_alu(inst):
    op = (inst & 0x01c0) >> 6
    Rs = (inst & 0x0038) >> 3
    Rd = (inst & 0x0007)
    ops = ["AND", "XOR", "LSL", "LSR",
           "ASR", "ADC", "SBC", "ROR",
           "TST", "NEG", "CMP", "CMN",
           "ORR", "MUL", "BIC", "MVN"]
    return (ops[op], mkreg(Rd), mkreg(Rs))

conds ={0:"EQ", 1:"NE", 2:"CS", 3:"CC",
        4:"MI", 5:"PL", 6:"VS", 7:"VC",
        8:"HI", 9:"LS", 10:"GE", 11:"LT",
        12:"GT", 13:"LE", 14:"UD"}

def decode_bcc(inst):
    cond = (inst & 0x0f00) >> 8
    if cond == 15:
        swi_nr = inst & 0x00ff
        return ("SWI", swi_nr)
    offset = inst & 0x00ff
    if offset & 0x80:
        offset -= 0x100
    offset = offset << 1
    return ("B"+conds[cond], offset)

def decode_stub(inst):
    return ("UNSUPPORTED", )

encs = [decode_stub,
        decode_stub,
        decode_alu_imm,
        decode_alu_imm,
        decode_alu,
        decode_stub,
        decode_stub,
        decode_stub,
        decode_stub,
        decode_stub,
        decode_stub,
        decode_push_pop,
        decode_stub,
        decode_bcc,
        decode_stub,
        decode_stub]

def disassemble_instruction(inst):
    inst = u16(inst)
    inst_enc = (inst & 0xf000) >> 12
    return encs[inst_enc](inst)

def disassemble_all(data, addr=0):
    while data != "":
        yield (addr, disassemble_instruction(data[:2]))
        addr += 2
        data = data[2:]


if __name__ == "__main__":
    print disassemble_instruction("03bd".decode("hex"))
    print disassemble_instruction("4130".decode("hex"))
    print disassemble_instruction("0f40".decode("hex"))
    print disassemble_instruction("4130".decode("hex"))
    print disassemble_instruction("fed0".decode("hex"))
    print disassemble_instruction("bfb9".decode("hex"))
    print disassemble_instruction("00df".decode("hex"))
