import thumb
import pyelf
import sys
import struct

p32 = lambda x: struct.pack("<L", x)

class ROP:
    def __init__(self, f):
        if type(f) == str:
            f = open(f, "r")
        if type(f) == file:
            f = pyelf.ELFFile(f)
        text_sec = f.getsection(".text")
        text_data = text_sec.data
        text_addr = text_sec.addr
        self.disassembly = list(thumb.disassemble_all(text_data, text_addr))
        self.pop_pc = filter(
                lambda (addr, inst): inst[0] == "POP" and "R15" in inst[1],
                self.disassembly)
        self.find_syscall_gadget()
        self.ropchain = []

    def find_syscall_gadget(self):
        self.swi_0 = None
        for i in range(len(self.disassembly)-1):
            addr, inst = self.disassembly[i]
            if inst != ("SWI", 0):
                continue
            addr2, inst2 = self.disassembly[i+1]
            if inst2[0] == "POP" and "R15" in inst2[1]:
                if self.swi_0 and len(inst2[1]) > len(self.swi_0[1][1]):
                    continue
                self.swi_0 = (addr, inst2)

    def pop_gadget_score(self, gadget, regs):
        return len(set(gadget[1]) & regs)
        matching = len(set(gadget[1]) & regs)
        unneeded = len(set(gadget[1]) - regs)
        return matching*16-unneeded

    def set_regs(self, **regs_dict):
        ropchain = []
        regs = set(map(lambda x: x.upper(), regs_dict.keys()))
        while regs:
            addr, inst = max(self.pop_pc,
                    key=lambda (addr, inst): self.pop_gadget_score(inst, regs))
            ropchain.append(addr | 1)
            ropchain += [regs_dict.get(reg, 0x41414141) for reg in inst[1][:-1]]
            regs -= set(inst[1])

        if regs:
            raise Exception("Unable to set registers %r from %r" % (regs, regs_dict))

        return ropchain

    def do_swi(self, **regs_dict):
        ropchain = []
        if self.swi_0 == None:
            raise Exception("SWI 0 gadget not found, Cannot not perform syscall")
        addr, pop_inst = self.swi_0
        ropchain.append(addr | 1)
        ropchain += [regs_dict.get(reg, 0x41414141) for reg in pop_inst[1][:-1]]
        return ropchain

    def do_syscall(self, **regs_dict):
        ropchain = self.set_regs(**regs_dict)
        ropchain += self.do_swi()
        return ropchain

    def syscall(self, **regs_dict):
        regs_dict2 = {}
        for k,v in regs_dict.items():
            regs_dict2[k.upper()] = v
        self.ropchain += self.do_syscall(**regs_dict2)

    def flush(self):
        ropchain = "".join(map(p32, self.ropchain))
        self.ropchain = []
        return ropchain