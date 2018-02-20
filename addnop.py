#!/usr/bin/python

import sys
from elftools.elf.elffile import ELFFile
from multiverse import Rewriter
from x64_assembler import _asm

def count_instruction(inst):
  template = '''
  nop
  '''
  inc = template
  return _asm( inc )

if __name__ == '__main__':
  if len(sys.argv) == 2:
    f = open(sys.argv[1])
    e = ELFFile(f)
    entry_point = e.header.e_entry
    f.close()
    #write_so = False, exec_only = True, no_pic = True
    rewriter = Rewriter(False,True,False)
    rewriter.set_before_inst_callback(count_instruction)
    rewriter.rewrite(sys.argv[1],'x86-64')
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
