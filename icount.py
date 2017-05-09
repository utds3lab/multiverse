#!/usr/bin/python

import sys
from elftools.elf.elffile import ELFFile
from renabler import Rewriter
from assembler import _asm

entry_point = 0
global_addr = 0

def count_instruction(inst):
  increment_template = '''
  push ax
  lahf
  seto al
  add DWORD PTR [0x%x],1
  adc DWORD PTR [0x%x],0
  cmp al,0x81
  sahf
  pop ax
  '''
  inc = increment_template%( global_addr, global_addr+4 )
  #Don't need to do the following because we initialize to 0 and are incrementing instead of decrementing
  #use global_sysinfo temporarily, until we have an actual way to allocate space for user scripts
  #Therefore, this will NOT WORK if we also write shared objects.
  #If it's the entry point, initialize to all 1s
  #if inst.address == entry_point:
  #  return _asm( 'mov DWORD PTR [0x%x], 0xffffffff\n%s'%( renabler.context.global_sysinfo, dec ) )
  return _asm( inc )

if __name__ == '__main__':
  if len(sys.argv) == 2:
    f = open(sys.argv[1])
    e = ELFFile(f)
    entry_point = e.header.e_entry
    f.close()
    #write_so = False, exec_only = True, no_pic = True
    rewriter = Rewriter(False,True,True)
    global_addr = rewriter.alloc_globals(8) #8 bytes
    rewriter.set_before_inst_callback(count_instruction)
    rewriter.rewrite(sys.argv[1])
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
