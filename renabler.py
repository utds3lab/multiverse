#!/usr/bin/python
from elftools.elf.elffile import ELFFile
import capstone
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
import sys
import struct
from pwn import asm,context
context(os='linux',arch='i386')

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
plt = {}
#TODO: Set actual address of function
lookup_function_offset = 0x8f
#List of library functions that have callback args; each function in the dict has a list of
#the arguments passed to it that are a callback (measured as the index of which argument it is)
#TODO: Handle more complex x64 calling convention
#TODO: Should I count _rtlf_fini (offset 5)?  It seems to be not in the binary
callbacks = {'__libc_start_main':[0,3,4]}


#Do stuff with call/jmp to anything in plt to check for functions with callbacks

def remap_target(ins,mapping,target,offs): #Only works for statically identifiable targets
  newtarget = '0x8f'
  if mapping is not None and target in mapping:#Second pass, known mapping
    newtarget = mapping[target]-(mapping[ins.address]+offs) #Offset from curr location in mapping
    newtarget = hex(newtarget)
    print "original target: %s"%hex(target)
    print "%s-(%s+%s) = %s"%(hex(mapping[target]),hex(mapping[ins.address]),hex(offs),newtarget)
  return newtarget

def in_plt(target):
  return target in range(plt['addr'],plt['addr']+plt['size'])

def get_plt_entry(target):
  #It seems that an elf does not directly give a mapping from each entry in the plt.
  #Instead, it maps from the got entries instead, making it unclear exactly where objdump
  #gets the information.  For our purposes, since all the entries in the plt jump to the got
  #entry, we can read the destination address from the jmp instruction.
  #TODO: ensure works for x64
  offset = target - plt['addr'] #Get the offset into the plt
  dest = plt['data'][offset+2:offset+2+4] #Get the four bytes of the GOT address
  dest = struct.unpack('<I',dest)[0] #Convert to integer, respecting byte endianness
  if dest in plt['entries']:
    return plt['entries'][dest] #If there is an entry, return that; the name of the function
  return None #Some entries may be a jump to the start of the plt (no entry)

def get_callback_code(ins,mapping,name):
  print 'call with callback found'
  #TODO: Why -12?  Is this general?
  save_eax = save_reg_template%('-12','eax')
  callback_template_before = '''
  mov eax, [esp+(%s*4)]'''
  callback_template_after = '''
  call $+%s
  mov [esp+(%s*4)], eax
  '''
  code = asm(save_eax) #Assemble the code to save eax
  for ind in callbacks[name]: #For each callback parameter in the stack
    cb_before = callback_template_before%ind
    code+=asm(cb_before) #Assemble the code to save the value at that stack offset to eax
    size=len(code) #Since jmp/call is relative, need the address we're coming from
    lookup_target = remap_target(ins,mapping,lookup_function_offset,size)
    cb_after = callback_template_after%(lookup_target,ind)
    code+=asm(cb_after)
  restore_eax = restore_reg_template%('eax','-12')
  code+=asm(restore_eax)
  return code

def translate_uncond(ins,mapping):
  op = ins.operands[0] #Get operand
  if op.type == X86_OP_REG: # e.g. call eax or jmp ebx
    pass
  elif op.type == X86_OP_MEM: # e.g. call [eax + ecx*4 + 0xcafebabe] or jmp [ebx+ecx]
    pass
  elif op.type == X86_OP_IMM: # e.g. call 0xdeadbeef or jmp 0xcafebada
    target = op.imm
    callback_code = b'' #If this ends up not being a plt call with callbacks, add no code
    if in_plt(target):
      print 'plt found @%s: %s %s'%(hex(ins.address),ins.mnemonic,ins.op_str)
      entry = get_plt_entry(target)
      if entry is not None and entry in callbacks.keys():
        callback_code = get_callback_code(ins,mapping,entry)
    newtarget = remap_target(ins,mapping,target,len(callback_code))
    print "(pre)new length: %s"%len(callback_code)
    print "target: %s"%hex(target)
    print "newtarget: %s"%newtarget
    patched = asm(ins.mnemonic + ' $+' + newtarget)
    if len(patched) == 2: #Short encoding, which we do not want
      patched+='\x90\x90\x90' #Add padding of 3 NOPs
    print "new length: %s"%len(callback_code+patched)
    return callback_code+patched
  return None

def translate_cond(ins,mapping):
  if ins.mnemonic in ['jcxz','jecxz']: #These instructions have no long encoding
    return None #TODO: handle special case for these instructions
  else:
    #print ins.mnemonic +' ' +ins.op_str
    #print dir(ins)
    #print ins.op_count()
    #print ins.operands
    target = ins.operands[0].imm # int(ins.op_str,16) The destination of this instruction
    newtarget = remap_target(ins,mapping,target,0)
    patched = asm(ins.mnemonic + ' $+' + newtarget)
    #TODO: some instructions encode to 6 bytes, some to 5, some to 2.  How do we know which?
    #For example, for CALL, it seems to only be 5 or 2 depending on offset.
    #But for jg, it can be 2 or 6 depending on offset, I think because it has a 2-byte opcode.
    while len(patched) < 6: #Short encoding, which we do not want
      patched+='\x90' #Add padding of NOPs
    #print "(cond)new length: %s"%len(patched)
    return patched

def translate_one(ins,mapping):
  if ins.mnemonic in ['call','jmp']: #Unconditional jump
    return translate_uncond(ins,mapping)
  elif ins.mnemonic in JCC: #Conditional jump
    return translate_cond(ins,mapping)
  else: #Any other instruction
    return None #No translation needs to be done

def gen_mapping(md,bytes,base):
  mapping = {}
  newoff = 0
  for off in range(0,len(bytes)):
    insts = md.disasm(bytes[off:off+15],base+off)#longest possible x86/x64 instr is 15 bytes
    try:
      ins = insts.next()
      mapping[base+off] = newoff
      newins = translate_one(ins,None)#In this pass, the mapping is incomplete
      if newins is not None:
        newoff+=len(newins)
      else:
        newoff+=1
    except StopIteration:
      newoff+=1 #Just move forward one byte
  #Now that the mapping is complete, we can add the mapping of the lookup function to the end
  #TODO: Perhaps it would be more efficient if we guaranteed the function to be aligned?
  global lookup_function_offset
  lookup_function_offset = len(bytes)+base #Where we pretend it was in the old code (after the end)
  mapping[len(bytes)+base] = newoff #Should be one after the last instruction in the new mapping
  print 'lookup mapping %s:%s'%(hex(lookup_function_offset),hex(newoff+base))
  return mapping

def gen_newcode(md,bytes,base,mapping):
  newbytes = b''
  for off in range(0,len(bytes)):
    insts = md.disasm(bytes[off:off+15],base+off)#longest possible x86/x64 instr is 15 bytes
    try:
      ins = insts.next()
      newins = translate_one(ins,mapping)#The mapping is now complete
      if newins is not None:
        #print '%s'%newins.encode('hex')
        tmps = md.disasm(newins,base+mapping[base+off])
        print 'off: %x mapping[base+off]: %x len(newbytes): %x '%(off,mapping[base+off],len(newbytes))
        for tmp in tmps:
          print '0x%x(0x%x):\t%s\t%s'%(tmp.address,len(newbytes)+base,tmp.mnemonic,tmp.op_str)
        print '---'
        newbytes+=newins #newins is simply the bytes of an assembled instruction
      else:
        newbytes+=bytes[off]
    except StopIteration:
      newbytes+=bytes[off] #No change, just add byte
  #TODO: Right here append the actual code for the lookup function onto the end of newbytes
  return newbytes

def renable(fname):
  offs = size = addr = 0
  with open(fname,'rb') as f:
    elffile = ELFFile(f)
    relplt = None
    dynsym = None
    for section in elffile.iter_sections():
      if section.name == '.text':
        print "Found .text"
        offs = section.header.sh_offset
        size = section.header.sh_size
        addr = section.header.sh_addr
      if section.name == '.plt':
        global plt
        #plt = section
        plt['addr'] = section.header['sh_addr']
        plt['size'] = section.header['sh_size']
        plt['data'] = section.data()
      if section.name == '.rel.plt': #TODO: x64 has .rela.plt
        relplt = section
      if section.name == '.dynsym':
        dynsym = section
    plt['entries'] = {}
    for rel in relplt.iter_relocations():
      got_off = rel['r_offset'] #Get GOT offset address for this entry
      ds_ent = ELF32_R_SYM(rel['r_info']) #Get offset into dynamic symbol table
      name = dynsym.get_symbol(ds_ent).name #Get name of symbol
      plt['entries'][got_off] = name #Insert this mapping from GOT offset address to symbol name
    print plt
    for seg in elffile.iter_segments():
      if seg.header['p_flags'] == 5 and seg.header['p_type'] == 'PT_LOAD': #Executable load seg
        print "Base address: %s"%hex(seg.header['p_vaddr'])
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32) #TODO: Allow to toggle 32/64
        md.detail = True
        bytes = seg.data()
        base = seg.header['p_vaddr']
        mapping = gen_mapping(md,bytes,base)
        newbytes = gen_newcode(md,bytes,base,mapping)
        #(mapping,newbytes) = translate_all(seg.data(),seg.header['p_vaddr'])
        #insts = md.disasm(newbytes[0x8048360-seg.header['p_vaddr']:0x8048441-seg.header['p_vaddr']],0x8048360)
        #The "mysterious" bytes between the previously patched instruction 
        #(originally at 0x804830b) are the remaining bytes from that jmp instruction!
        #So even though there was nothing between that jmp at the end of that plt entry
        #and the start of the next plt entry, now there are 4 bytes from the rest of the jmp.
        #This is a good example of why I need to take a different approach to generating the mapping.
        insts = md.disasm(newbytes[0x80483af-seg.header['p_vaddr']:0x80483bf-seg.header['p_vaddr']],0x80483af)
        for ins in insts:
          print '0x%x:\t%s\t%s'%(ins.address,ins.mnemonic,ins.op_str)
        tmpdct = {hex(k): (lambda x:hex(x+seg.header['p_vaddr']))(v) for k,v in mapping.items()}
        keys = tmpdct.keys()
        keys.sort()
        output = ''
        for key in keys:
          output+='%s:%s '%(key,tmpdct[key])
        #print output
          
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
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
