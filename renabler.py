#!/usr/bin/python
from elftools.elf.elffile import ELFFile
import capstone
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
import sys
import struct
#from pwn import asm,context
#context(os='linux',arch='i386')
from assembler import asm,_asm
import assembler
import cProfile
import bin_write
import json
import os
import re

import context

#From Brian's Static_phase.py
JCC = ['jo','jno','js','jns','je','jz','jne','jnz','jb','jnae',
  'jc','jnb','jae','jnc','jbe','jna','ja','jnbe','jl','jnge','jge',
  'jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']

save_reg_template = '''
mov DWORD PTR [esp%s], %s
'''
restore_reg_template = '''
mov %s, DWORD PTR [esp%s]
'''

save_register = '''
mov %s, -12
mov %s, %s'''

memory_ref_string = re.compile(u'^dword ptr \[(?P<address>0x[0-9a-z]+)\]$')

'''
call X
'''#%('eax',cs_insn.reg_name(opnd.reg),'eax')
'''
class Context(object):
  def __init__():
    self'''

#Transforms the 'r_info' field in a relocation entry to the offset into another table
#determined by the host reloc table's 'sh_link' entry.  In our case it's the dynsym table.
def ELF32_R_SYM(val):
  return (val) >> 8

#Globals: If there end up being too many of these, put them in a Context & pass them around
context = Context()
'''plt = {}
newbase = 0x09000000
#TODO: Set actual address of function
lookup_function_offset = 0x8f
secondary_lookup_function_offset = 0x8f #ONLY used when rewriting ONLY main executable
mapping_offset = 0x8f
global_sysinfo = 0x8f	#Address containing sysinfo's address
global_flag = 0x8f
global_lookup = 0x7000000	#Address containing global lookup function
popgm = 'popgm'
popgm_offset = 0x8f
new_entry_off = 0x8f
write_so = False
exec_only = False
no_pic = False
get_pc_thunk = None
stat = {}
stat['indcall'] = 0
stat['indjmp'] = 0
stat['dircall'] = 0
stat['dirjmp'] = 0
stat['jcc'] = 0
stat['ret'] = 0
stat['origtext'] = 0
stat['newtext'] = 0
stat['origfile'] = 0
stat['newfile'] = 0
stat['mapsize'] = 0
stat['lookupsize'] = 0
#stat['auxvecsize'] = 0
#stat['globmapsize'] = 0
#stat['globlookupsize'] = 0
#List of library functions that have callback args; each function in the dict has a list of
#the arguments passed to it that are a callback (measured as the index of which argument it is)
#TODO: Handle more complex x64 calling convention
#TODO: Should I count _rtlf_fini (offset 5)?  It seems to be not in the binary
callbacks = {'__libc_start_main':[0,3,4]}'''

# NEW PROTOTYPE INSTRUMENTATION FUNCTIONS -- NOT FINAL
# Using a different approach than last time
before_inst_callback = (lambda x: None)

def set_before_inst_callback(func):
  '''Pass a function that will be called when translating each instruction.
     This function should accept an instruction argument (the instruction type returned from capstone),
     which can be read to determine what code to insert (if any).  A byte string of assembled bytes
     should be returned to be inserted before the instruction, or if none are to be inserted, return None.

     NOTE: NOTHING is done to protect the stack, registers, flags, etc!  If ANY of these are changed, there
     is a chance that EVERYTHING will go wrong!  Leave everything as you found it or suffer the consequences!
  '''
  global before_inst_callback
  before_inst_callback = func

from brute_force_disassembler import BruteForceDisassembler
disassembler = None

def temp_init_disasm(arch,bytes,base,entry):
  global disassembler
  disassembler = BruteForceDisassembler(arch)

def gen_mapping(bytes,base):
    print 'Generating mapping...'
    mapping = {}
    maplist = []
    currmap = {}
    last = None #Last instruction disassembled
    reroute = assembler.asm('jmp $+0x8f') #Dummy jmp to imitate connecting jmp; we may not know dest yet
    for ins in disassembler.disasm(bytes,base):
      if ins is None and last is not None: # Encountered a previously disassembled instruction and have not redirected
        currmap[last.address] += len(reroute)
        last = None #If we have not found any more new instructions since our last redirect, don't redirect again
        maplist.append(currmap)
        currmap = {}
      elif ins is not None:
        last = ins #Remember the last disassembled instruction
        newins = translate_one(ins,None) #In this pass, the mapping is incomplete
        if newins is not None:
          currmap[ins.address] = len(newins)
        else:
          currmap[ins.address] = len(ins.bytes)
    context.lookup_function_offset = 0 #Place lookup function at start of new text section
    lookup_size = len(get_lookup_code(base,len(bytes),0,0x8f)) #TODO: Issue with mapping offset & size
    offset = lookup_size
    if context.exec_only:
      context.secondary_lookup_function_offset = offset
      secondary_lookup_size = len(get_secondary_lookup_code(base,len(bytes),offset,0x8f))
      offset += secondary_lookup_size
    for m in maplist:
      for k in sorted(m.keys()):
        size = m[k]
        mapping[k] = offset
        offset+=size #Add the size of this instruction to the total offset
    #Now that the mapping is complete, we know the length of it
    context.mapping_offset = len(bytes)+base #Where we pretend the mapping was in the old code
    if not context.write_so:
      context.new_entry_off = offset #Set entry point to start of auxvec
      offset+=len(get_auxvec_code(0x8f))#Unknown entry addr here, but not needed b/c we just need len
    mapping[context.lookup_function_offset] = context.lookup_function_offset
    if context.exec_only:
      #This is a very low number and therefore will not be written out into the final mapping.
      #It is used to convey this offset for the second phase when generating code, specifically
      #for the use of remap_target.  Without setting this it always sets the target to 0x8f. Sigh.
      mapping[context.secondary_lookup_function_offset] = context.secondary_lookup_function_offset
    #Don't yet know mapping offset; we must compute it
    mapping[len(bytes)+base] = offset
    if not context.write_so:
      #For NOW, place the global data/function at the end of this because we can't necessarily fit
      #another section.  TODO: put this somewhere else
      #The first time, sysinfo's and flag's location is unknown,
      #so they are wrong in the first call to get_global_lookup_code
      #However, the global_flag is moving to a TLS section, so it takes
      #up no space in the global lookup
      #global_flag = global_lookup + len(get_global_lookup_code())
      #popgm goes directly after the global lookup, and global_sysinfo directly after that.
      context.popgm_offset = len(get_global_lookup_code())
      context.global_sysinfo = context.global_lookup + context.popgm_offset + len(get_popgm_code())
      #Now that this is set, the auxvec code should work
    return mapping

def write_mapping(mapping,base,size):
  bytes = b''
  for addr in range(base,base+size):
    if addr in mapping:
      bytes+=struct.pack('<I',mapping[addr]) #Write our offset in little endian
    else:
      #print 'No mapping for 0x%x'%addr
      bytes+=struct.pack('<I',0xffffffff) #Write an invalid offset if not in mapping
  print 'last address in mapping was 0x%x'%(base+size)
  return bytes

def gen_newcode(mapping,bytes,base,entry):
    print 'Generating new code...'
    newbytes = ''
    bytemap = {}
    maplist = []
    last = None #Last instruction disassembled
    for ins in disassembler.disasm(bytes,base):
      if ins is None and last is not None: # Encountered a previously disassembled instruction and have not redirected
        target = last.address + len(last.bytes) #address of where in the original code we would want to jmp to
        next_target = remap_target(last.address, mapping, target, len(bytemap[last.address]) )
        reroute = assembler.asm( 'jmp $+%s'%(next_target) )
        if len(reroute) == 2: #Short encoding, which we do not want
          reroute+='\x90\x90\x90' #Add padding of 3 NOPs
        bytemap[last.address] += reroute
        last = None
        maplist.append(bytemap)
        bytemap = {}
      elif ins is not None:
        last = ins
        newins = translate_one(ins,mapping) #In this pass, the mapping is incomplete
        if newins is not None:
          bytemap[ins.address] = newins #Old address maps to these new instructions
        else:
          bytemap[ins.address] = str(ins.bytes) #This instruction is unchanged, and its old address maps to it
    #Add the lookup function as the first thing in the new text section
    newbytes+=get_lookup_code(base,len(bytes),context.lookup_function_offset,mapping[context.mapping_offset])
    if context.exec_only:
      newbytes += get_secondary_lookup_code(base,len(bytes),context.secondary_lookup_function_offset,mapping[context.mapping_offset])
    count = 0
    for m in maplist:
      for k in sorted(m.keys()): #For each original address to code, in order of original address
        newbytes+=m[k]
    if not context.write_so:
      newbytes+=get_auxvec_code(mapping[entry])
    #Append mapping to end of bytes
    newbytes+=write_mapping(mapping,base,len(bytes))
    return newbytes

def write_global_mapping_section():
  globalbytes = get_global_lookup_code()
  #globalbytes+='\0' #flag field
  globalbytes+=get_popgm_code()
  globalbytes+='\0\0\0\0' #sysinfo field
  #Global mapping (0x3ffff8 0xff bytes) ending at kernel addresses.  Note it is NOT ending
  #at 0xc0000000 because this boundary is only true for 32-bit kernels.  For 64-bit kernels,
  #the application is able to use most of the entire 4GB address space, and the kernel only
  #holds onto a tiny 8KB at the top of the address space.
  globalbytes+='\xff'*((0xffffe000>>12)<<2) 
  return globalbytes

#Find the earliest address we can place the new code
def find_newbase(elffile):
  maxaddr = 0
  for seg in elffile.iter_segments():
    segend = seg.header['p_vaddr']+seg.header['p_memsz']
    if segend > maxaddr:
      maxaddr = segend
  maxaddr += ( 0x1000 - maxaddr%0x1000 ) # Align to page boundary
  return maxaddr


def renable(fname):
  offs = size = addr = 0
  with open(fname,'rb') as f:
    elffile = ELFFile(f)
    relplt = None
    dynsym = None
    entry = elffile.header.e_entry #application entry point
    for section in elffile.iter_sections():
      if section.name == '.text':
        print "Found .text"
        offs = section.header.sh_offset
        size = section.header.sh_size
        addr = section.header.sh_addr
      if section.name == '.plt':
        context.plt['addr'] = section.header['sh_addr']
        context.plt['size'] = section.header['sh_size']
        context.plt['data'] = section.data()
      if section.name == '.rel.plt': #TODO: x64 has .rela.plt
        relplt = section
      if section.name == '.dynsym':
        dynsym = section
      if section.name == '.symtab':
        for sym in section.iter_symbols():
          if sym.name == '__x86.get_pc_thunk.bx':
            context.get_pc_thunk = sym.entry['st_value'] #Address of thunk
        #section.get_symbol_by_name('__x86.get_pc_thunk.bx')) #Apparently this is in a newer pyelftools
    plt['entries'] = {}
    if relplt is not None:
      for rel in relplt.iter_relocations():
        got_off = rel['r_offset'] #Get GOT offset address for this entry
        ds_ent = ELF32_R_SYM(rel['r_info']) #Get offset into dynamic symbol table
        if dynsym:
          name = dynsym.get_symbol(ds_ent).name #Get name of symbol
          context.plt['entries'][got_off] = name #Insert this mapping from GOT offset address to symbol name
    else:
        print 'binary does not contain plt'
    if context.write_so:
      print 'Writing as .so file'
      context.newbase = find_newbase(elffile)
    elif context.exec_only:
      print 'Writing ONLY main binary, without support for rewritten .so files'
      context.newbase = 0x09000000
    else:
      print 'Writing as main binary'
      context.newbase = 0x09000000
    if context.no_pic:
      print 'Rewriting without support for generic PIC'
    for seg in elffile.iter_segments():
      if seg.header['p_flags'] == 5 and seg.header['p_type'] == 'PT_LOAD': #Executable load seg
        print "Base address: %s"%hex(seg.header['p_vaddr'])
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32) #TODO: Allow to toggle 32/64
        md.detail = True
        bytes = seg.data()
        base = seg.header['p_vaddr']
        temp_init_disasm('x86',bytes,base,entry)
        mapping = gen_mapping(bytes,base)
        newbytes = gen_newcode(mapping,bytes,base,entry)
        #Perhaps I could find a better location to set the value of global_flag
        #(which is the offset from gs)
        #I only need one byte for the global flag, so I am adding a tiny bit to TLS
        #add_tls_section returns the offset, but we must make it negative
        context.global_flag = -bin_write.add_tls_section(fname,b'\0')
        print 'just set global_flag value to 0x%x'%context.global_flag
        #maptext = write_mapping(mapping,base,len(bytes))
        #(mapping,newbytes) = translate_all(seg.data(),seg.header['p_vaddr'])
        #insts = md.disasm(newbytes[0x8048360-seg.header['p_vaddr']:0x8048441-seg.header['p_vaddr']],0x8048360)
        #The "mysterious" bytes between the previously patched instruction 
        #(originally at 0x804830b) are the remaining bytes from that jmp instruction!
        #So even though there was nothing between that jmp at the end of that plt entry
        #and the start of the next plt entry, now there are 4 bytes from the rest of the jmp.
        #This is a good example of why I need to take a different approach to generating the mapping.
        #insts = md.disasm(newbytes[0x80483af-seg.header['p_vaddr']:0x80483bf-seg.header['p_vaddr']],0x80483af)
        #insts = md.disasm(newbytes,0x8048000)
        #for ins in insts:
        #  print '0x%x:\t%s\t%s'%(ins.address,ins.mnemonic,ins.op_str)
        #tmpdct = {hex(k): (lambda x:hex(x+seg.header['p_vaddr']))(v) for k,v in mapping.items()}
        #keys = tmpdct.keys()
        #keys.sort()
        #output = ''
        #for key in keys:
        #  output+='%s:%s '%(key,tmpdct[key])
        with open('newbytes','wb') as f2:
          f2.write(newbytes)
        if not context.write_so:
          with open('newglobal','wb') as f2:
            f2.write(write_global_mapping_section())
        #print output
        print mapping[base]
        print mapping[base+1]
        maptext = write_mapping(mapping,base,len(bytes))
        cache = ''
        for x in maptext:
          #print x
          cache+='%d,'%int(x.encode('hex'),16)
        #print cache
	#print maptext.encode('hex')
        print '0x%x'%(base+len(bytes))
	print 'code increase: %d%%'%(((len(newbytes)-len(bytes))/float(len(bytes)))*100)
        lookup = get_lookup_code(base,len(bytes),context.lookup_function_offset,0x8f)
        print 'lookup w/unknown mapping %s'%len(lookup)
        insts = md.disasm(lookup,0x0)
	for ins in insts:
          print '0x%x:\t%s\t%s\t%s'%(ins.address,str(ins.bytes).encode('hex'),ins.mnemonic,ins.op_str)
        lookup = get_lookup_code(base,len(bytes),context.lookup_function_offset,mapping[context.mapping_offset])
        print 'lookup w/known mapping %s'%len(lookup)
        insts = md.disasm(lookup,0x0)
	for ins in insts:
          print '0x%x:\t%s\t%s\t%s'%(ins.address,str(ins.bytes).encode('hex'),ins.mnemonic,ins.op_str)
        if 0x80482b4 in mapping:
		print 'simplest only: _init at 0x%x'%mapping[0x80482b4]
        if 0x804ac40 in mapping:
		print 'bzip2 only: snocString at 0x%x'%mapping[0x804ac40]
        if not context.write_so:
          print 'new entry point: %x'%context.new_entry_off
          print 'new _start point: %x'%mapping[entry]
          print 'global lookup: 0x%x'%context.global_lookup
        print 'local lookup: 0x%x'%context.lookup_function_offset
        print 'secondary local lookup: 0x%x'%context.secondary_lookup_function_offset
        with open('%s-r-map.json'%fname,'wb') as f:
          json.dump(mapping,f)
        if not context.write_so:
          bin_write.rewrite(fname,fname+'-r','newbytes',context.newbase,write_global_mapping_section(),context.global_lookup,context.newbase+context.new_entry_off)
        else:
          context.new_entry_off = mapping[entry]
          bin_write.rewrite_noglobal(fname,fname+'-r','newbytes',context.newbase,context.newbase+context.new_entry_off)
        context.stat['origtext'] = len(bytes)
        context.stat['newtext'] = len(newbytes)
        context.stat['origfile'] = os.path.getsize(fname)
        context.stat['newfile'] = os.path.getsize(fname+'-r')
        context.stat['mapsize'] = len(maptext)
        context.stat['lookupsize'] = \
          len(get_lookup_code(base,len(bytes),context.lookup_function_offset,mapping[context.mapping_offset]))
        if context.exec_only:
          context.stat['secondarylookupsize'] = \
            len(get_secondary_lookup_code(base,len(bytes), \
              context.secondary_lookup_function_offset,mapping[context.mapping_offset]))
        if not context.write_so:
          context.stat['auxvecsize'] = len(get_auxvec_code(mapping[entry]))
          with open(context.popgm) as f:
            tmp=f.read()
            context.stat['popgmsize'] = len(tmp)
          context.stat['globmapsectionsize'] = len(write_global_mapping_section())
          context.stat['globlookupsize'] = len(get_global_lookup_code())
        with open('%s-r-stat.json'%fname,'wb') as f:
          json.dump(context.stat,f,sort_keys=True,indent=4,separators=(',',': '))
          
'''
  with open(fname,'rb') as f:
    f.read(offs)
    bytes = f.read(size)
    (mapping,newbytes) = translate_all(bytes,addr)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in range(0,size):
      #print dir(md.disasm(bytes[i:i+15],addr+i))
      insts = md.disasm(newbytes[i:i+15],addr+i)
      ins = None
      try:
        ins = insts.next()#longest possible x86/x64 instruction is 15 bytes
        #print str(ins.bytes).encode('hex')
        #print ins.size
        #print dir(ins)
      except StopIteration:
        pass
      if ins is None:
        pass#print 'no legal decoding'
      else:
      	pass#print '0x%x:\t%s\t%s'%(ins.address,ins.mnemonic,ins.op_str)
    print {k: (lambda x:x+addr)(v) for k,v in mapping.items()}
    print asm(save_register%('eax','eax','eax')).encode('hex')'''
    
if __name__ == '__main__':
  if len(sys.argv) == 2:
    renable(sys.argv[1])
    #cProfile.run('renable(sys.argv[1])')
  elif len(sys.argv) == 3 and sys.argv[1] == '-so':
    context.write_so = True
    renable(sys.argv[2])
  elif len(sys.argv) == 3 and sys.argv[1] == '-execonly':
    context.exec_only = True
    renable(sys.argv[2])
  elif len(sys.argv) == 4 and ( (sys.argv[1] == '-execonly' and sys.argv[2] == '-nopic') or (sys.argv[2] == '-execonly' and sys.argv[1] == '-nopic') ):
    context.exec_only = True
    context.no_pic = True
    renable(sys.argv[3])
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s [-so/[-execonly [-nopic]]] <filename>"%sys.argv[0]
