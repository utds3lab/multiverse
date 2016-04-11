import sys
sys.path.insert(0,'/home/erick/git/delinker/Delinker/src')
from ELFManip import ELFManip

if len(sys.argv) != 2:
  print "needs filename"

fn = sys.argv[1]

elf = ELFManip(fn)

newcode = 'newbytes'

elf.add_section(newcode, sh_addr = 0x09000000)
#elf.set_entry_point(0x09000200) #teeny
#elf.set_entry_point(0x09000854) #simplest main
elf.set_entry_point(0x09000230) #eip

elf.write_new_elf('relocated')

