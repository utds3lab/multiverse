#!/usr/bin/python

import sys
from elftools.elf.elffile import ELFFile
import renabler
from assembler import _asm

entry_point = 0

def count_instruction(inst):
  decrement_template = '''
  push ecx
  mov ecx, DWORD PTR [0x%x]
  loop next
next:
  mov DWORD PTR [0x%x], ecx
  pop ecx
  '''
  dec = decrement_template%( renabler.global_sysinfo, renabler.global_sysinfo )
  #use global_sysinfo temporarily, until we have an actual way to allocate space for user scripts
  #Therefore, this will NOT WORK if we also write shared objects.
  #If it's the entry point, initialize to all 1s
  if inst.address == entry_point:
    return _asm( 'mov DWORD PTR [0x%x], 0xffffffff\n%s'%( renabler.global_sysinfo, dec ) )
  return _asm( dec )

if __name__ == '__main__':
  if len(sys.argv) == 2:
    f = open(sys.argv[1])
    e = ELFFile(f)
    entry_point = e.header.e_entry
    f.close()
    renabler.set_before_inst_callback(count_instruction)
    renabler.write_so = False
    renabler.exec_only = True
    renabler.no_pic = True
    renabler.renable(sys.argv[1])
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
