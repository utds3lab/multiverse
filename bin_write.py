import sys
sys.path.insert(0,'/home/erick/git/delinker/Delinker/src')
from ELFManip import ELFManip, Custom_Section, Custom_Segment
from Constants import PT_LOAD

def rewrite(fname,nname,newcode,newbase,entry):
  elf = ELFManip(fname)
  with open(newcode) as f:
    newbytes = f.read()
    newtext_section = Custom_Section(newbytes, sh_addr = newbase)
    if newtext_section is None:
      raise Exception
    newtext_segment = Custom_Segment(PT_LOAD)
    newtext_segment = elf.add_segment(newtext_segment)
    elf.add_section(newtext_section, newtext_segment)
    elf.set_entry_point(entry)
    elf.write_new_elf(nname)

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print "needs filename"

  fn = sys.argv[1]

  elf = ELFManip(fn)

  newcode = 'newbytes'

  elf.add_section(newcode, sh_addr = 0x09000000)
  #elf.set_entry_point(0x09000200) #teeny
  #elf.set_entry_point(0x09000854) #simplest main
  #elf.set_entry_point(0x09000230) #eip
  #elf.set_entry_point(0x09000228) #mem
  #elf.set_entry_point(0x09002278) #64-bit echo (which therefore wouldn't work regardless)
  #elf.set_entry_point(0x09000765) #simplest (_init at 0xc78)
  #elf.set_entry_point(0x0900026c) #lookup
  #(0x8048cf0 - 0x8048000)+0x59838 = 0x5a428 (lookup index)
  #elf.set_entry_point(0x09001ce8) #bzip2
  elf.set_entry_point(0x090013ef) #ssimplest

  elf.write_new_elf('relocated')

