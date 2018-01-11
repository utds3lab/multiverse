#!/usr/bin/python

import sys
from elftools.elf.elffile import ELFFile
from multiverse import Rewriter
from assembler import _asm

entry_point = 0
global_addr = 0

'''
  This counts the number of instructions in a 32-bit binary with an 8-byte counter.
  The counter is not printed at the end of execution, so a breakpoint must be set
  with a debugger and the value of the counter must be manually verified.
'''
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
  return _asm( inc )

if __name__ == '__main__':
  if len(sys.argv) == 2:
    f = open(sys.argv[1])
    e = ELFFile(f)
    entry_point = e.header.e_entry
    f.close()
    rewriter = Rewriter(False,True,True)
    global_addr = rewriter.alloc_globals(8) #8 bytes
    rewriter.set_before_inst_callback(count_instruction)
    rewriter.rewrite(sys.argv[1])
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
