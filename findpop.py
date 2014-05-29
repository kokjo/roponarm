import elf
import thumb

f = open("bookworm", "r")
elffile = elf.ELFFile(f)
text_section = elffile.getsection(".text")
text_data = text_section.data

addr = text_section.addr
seen = set()
gadgets = []
while text_data != "":
    inst = thumb.disassemble_instruction(text_data[:2])
    if (inst[0] == "POP") and ("R15" in inst[1]):
        if repr(inst) not in seen:
            seen.add(repr(inst))
            gadgets += [(addr, inst)]
    addr += 2
    text_data = text_data[2:]

for gadget in gadgets:
    print "0x%x: %r" % gadget
