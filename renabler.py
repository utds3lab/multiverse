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
lookup_function_addr = 0
#List of library functions that have callback args; each function in the dict has a list of
#the arguments passed to it that are a callback (measured as the offset into the stack in bytes)
#TODO: Handle more complex x64 calling convention
#TODO: Should I count _rtlf_fini (offset 5)?  It seems to be not in the binary
callbacks = {'__libc_start_main':[0,3,4]}


#Do stuff with call/jmp to anything in plt to check for functions with callbacks

def remap_target(ins,mapping,target,offs): #Only works for statically identifiable targets
  newtarget = '0x8f'
  if mapping is not None and target in mapping:#Second pass, known mapping
    newtarget = mapping[target]-mapping[ins.address]+offs #Offset from curr location in mapping
    newtarget = '0x'+str(newtarget).encode('hex')
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
    target = '0x8f'
    if mapping is not None:
      #TODO: The offsets this produces seem wrong.  Analyze and evaluate.
      target = lookup_function_addr-mapping[ins.address]+size
      target = '0x'+str(target).encode('hex')
    cb_after = callback_template_after%(target,ind)
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
      print 'plt found: %s %s'%(ins.mnemonic,ins.op_str)
      entry = get_plt_entry(target)
      if entry is not None and entry in callbacks.keys():
        callback_code = get_callback_code(ins,mapping,entry)
    newtarget = remap_target(ins,mapping,target,len(callback_code))
    return callback_code+asm(ins.mnemonic + ' $+' + newtarget)
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
    return asm(ins.mnemonic + ' $+' + newtarget)

def translate_one(ins,mapping):
  if ins.mnemonic in ['call','jmp']: #Unconditional jump
    return translate_uncond(ins,mapping)
  elif ins.mnemonic in JCC: #Conditional jump
    return translate_cond(ins,mapping)
  else: #Any other instruction
    return None #No translation needs to be done

def translate_all(bytes,base):
  mapping = {}
  newbytes = b''
  newoff = 0
  md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32) #TODO: Allow to toggle 32/64
  md.detail = True
  for off in range(0,len(bytes)):
    insts = md.disasm(bytes[off:off+15],base+off)#longest possible x86/x64 instr is 15 bytes
    try:
      ins = insts.next()
      mapping[off+base] = newoff
      newins = translate_one(ins,None)#In this pass, the mapping is incomplete
      if newins is not None:
        newoff+=len(newins)
      else:
        newoff+=1
    except StopIteration:
      newoff+=1#Just move forward one byte
  for off in range(0,len(bytes)):
    insts = md.disasm(bytes[off:off+15],base+off)#longest possible x86/x64 instr is 15 bytes
    try:
      ins = insts.next()
      newins = translate_one(ins,mapping)#The mapping is now complete
      if newins is not None:
        newbytes+=newins #newins is simply the bytes of an assembled instruction
        tmps = md.disasm(newins,base+off)
        for tmp in tmps:
          print '0x%x:\t%s\t%s'%(tmp.address,tmp.mnemonic,tmp.op_str)
        print '---'
      else:
        newbytes+=bytes[off]
    except StopIteration:
      newbytes+=bytes[off] #No change, just add byte
  return (mapping,newbytes)

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
        (mapping,newbytes) = translate_all(seg.data(),seg.header['p_vaddr'])
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        #print {k: (lambda x:x+addr)(v) for k,v in mapping.items()}
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
