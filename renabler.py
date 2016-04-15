#!/usr/bin/python
from elftools.elf.elffile import ELFFile
import capstone
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
import sys
import struct
#from pwn import asm,context
#context(os='linux',arch='i386')
from assembler import asm
import assembler
import cProfile

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
mapping_offset = 0x8f
get_pc_thunk = None
#List of library functions that have callback args; each function in the dict has a list of
#the arguments passed to it that are a callback (measured as the index of which argument it is)
#TODO: Handle more complex x64 calling convention
#TODO: Should I count _rtlf_fini (offset 5)?  It seems to be not in the binary
callbacks = {'__libc_start_main':[0,3,4]}


#Do stuff with call/jmp to anything in plt to check for functions with callbacks

def remap_target(addr,mapping,target,offs): #Only works for statically identifiable targets
  newtarget = '0x8f'
  if mapping is not None and target in mapping:#Second pass, known mapping
    newtarget = mapping[target]-(mapping[addr]+offs) #Offset from curr location in mapping
    newtarget = hex(newtarget)
    print "original target: %s"%hex(target)
    print "%s-(%s+%s) = %s"%(hex(mapping[target]),hex(mapping[addr]),hex(offs),newtarget)
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
    lookup_target = remap_target(ins.address,mapping,lookup_function_offset,size)
    cb_after = callback_template_after%(lookup_target,ind)
    code+=asm(cb_after)
  restore_eax = restore_reg_template%('eax','-12')
  code+=asm(restore_eax)
  return code

def get_direct_uncond_code(ins,mapping,target):
  #save_eax = save_reg_template%('-12','eax')
  #code:
  '''
  mov [esp-12], eax	;save old eax value
  mov eax, %s		;read location in memory from which we will get destination
  call $+%s		;call lookup function
  mov [esp-4], eax	;save new eax value (destination mapping)
  mov eax, [esp-12]	;restore old eax value
  %s [esp-4]		;jmp/call to new address
  '''
  template_before = '''
  mov [esp-12], eax
  mov eax, %s
  '''
  template_after = '''
  call $+%s
  mov [esp-4], eax
  mov eax, [esp-12]
  %s [esp-4]
  '''
  code = asm(template_before%(target))
  size = len(code)
  lookup_target = remap_target(ins.address,mapping,lookup_function_offset,size)
  code+=asm(template_after%(lookup_target,ins.mnemonic))
  return code

def get_lookup_code(base,size,lookup_off,mapping_off):
  #Example assembly for lookup function
  '''
	push edx
	mov edx,eax
	call get_eip
  get_eip:
	pop eax			;Get current instruction pointer
	sub eax,0x8248		;Subtract offset from instruction pointer val to get new text base addr
	sub edx,0x8048000	;Compare to start (exclusive) and set edx to an offset in the mapping
	jl outside		;Out of bounds (too small)
	cmp edx,0x220		;Compare to end (inclusive) (note we are now comparing to the size)
	jge outside		;Out of bounds (too big)
	mov edx,[mapping+edx*4]	;Retrieve mapping entry (can't do this directly in generated func)
	cmp edx, 0xffffffff	;Compare to invalid entry
	je failure		;It was an invalid entry
	add eax,edx		;Add the offset of the destination to the new text section base addr
	pop edx
	ret
  outside:			;If the address is out of the mapping bounds, return original address
	add edx,0x8048000	;Undo subtraction of base, giving us the originally requested address
	mov eax,edx		;Place the original request back in eax
	pop edx
	ret
  failure:
	hlt
  '''
  lookup_template = '''
	push edx
	mov edx,eax
	call get_eip
  get_eip:
	pop eax
	sub eax,%s
	sub edx,%s
	jl outside
	cmp edx,%s
	jge outside
	mov edx,[eax+edx*4+%s]
	cmp edx, 0xffffffff
	je failure
	add eax,edx
	pop edx
	ret
  outside:
	add edx,%s
	mov eax,edx
	pop edx
	ret
  failure:
	hlt
  '''
  #retrieve eip 8 bytes after start of lookup function
  return asm(lookup_template%(lookup_off+8,base,size,mapping_off,base)) 

def translate_uncond(ins,mapping):
  op = ins.operands[0] #Get operand
  if op.type == X86_OP_REG: # e.g. call eax or jmp ebx
    target = ins.reg_name(op.reg)
    return get_direct_uncond_code(ins,mapping,target)
  elif op.type == X86_OP_MEM: # e.g. call [eax + ecx*4 + 0xcafebabe] or jmp [ebx+ecx]
    target = ins.op_str
    return get_direct_uncond_code(ins,mapping,target)
  elif op.type == X86_OP_IMM: # e.g. call 0xdeadbeef or jmp 0xcafebada
    target = op.imm
    callback_code = b'' #If this ends up not being a plt call with callbacks, add no code
    if get_pc_thunk is not None and target == get_pc_thunk: #Special case for calls to thunk
      print 'Found call to get_pc_thunk at 0x%x'%ins.address
      thunk_ret = ins.address+len(ins.bytes) #Address directly after call instruction
      #Replace the call with a mov instruction setting ebx to what WOULD have been the
      #result in the original code, assuming that the original code is in its original place.
      return asm('mov ebx,%s'%thunk_ret)
    if in_plt(target):
      print 'plt found @%s: %s %s'%(hex(ins.address),ins.mnemonic,ins.op_str)
      entry = get_plt_entry(target)
      if entry is not None and entry in callbacks.keys():
        callback_code = get_callback_code(ins,mapping,entry)
    newtarget = remap_target(ins.address,mapping,target,len(callback_code))
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
    print "WARNING: encountered unhandled opcode %s"%ins.mnemonic
    return None #TODO: handle special case for these instructions
  else:
    #print ins.mnemonic +' ' +ins.op_str
    #print dir(ins)
    #print ins.op_count()
    #print ins.operands
    target = ins.operands[0].imm # int(ins.op_str,16) The destination of this instruction
    newtarget = remap_target(ins.address,mapping,target,0)
    print "target: %x remapped target: %s"%(target,newtarget)
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

def get_instr(md,bytes,instoff,base):
  return md.disasm(bytes[instoff:instoff+15],base+instoff)#longest x86/x64 instr is 15 bytes

def check(base,instoff,dummymap):
  off = base+instoff
  #for m in maplist:
  if off in dummymap:
    raise StopIteration

def brute_force_disasm(md,bytes,base,instoff,dummymap):
  '''insts = md.disasm(bytes[instoff:],base+instoff)
  instoff = base+instoff
  for ins in insts:
    for m in maplist:
      if instoff in m:
        raise StopIteration
    instoff+=len(ins.bytes)
    yield ins'''
  while instoff < len(bytes):
    check(base,instoff,dummymap)
    insts = get_instr(md,bytes,instoff,base)
    try:
      ins = insts.next() #May raise StopIteration
      instoff+=len(ins.bytes)
      yield ins
    except StopIteration: #Not a valid instruction
      instoff+=1
      yield None
  '''while instoff < len(bytes):
    in_mapping = False
    for m in maplist:
      if base+instoff in m:
        in_mapping = True
        break
    if in_mapping:
      break
    insts = md.disasm(bytes[instoff:instoff+15],base+instoff)#longest x86/x64 instr is 15 bytes
    try:
      ins = insts.next() #May raise StopIteration
      instoff+=len(ins.bytes)
      yield ins
    except StopIteration: #Not a valid instruction
      instoff+=1
      yield None'''

def gen_mapping(md,bytes,base):
  mapping = {}
  #Each mapping in maplist holds the length of that instruction (or instructions if patched)
  maplist = []
  dummymap = {}
  for off in range(0,len(bytes)):
    instoff = off #instruction offset is the offset in this decoding
    newoff = 0 #For each decoding, we have a new offset, starting at 0
    #Each mapping in maplist has offset from wherever it starts, so
    #when we put them together we have the freedom to shuffle their positions
    currmap = {}
    #print "[MAPPING] DOING OFFSET %s"%off
    for ins in brute_force_disasm(md,bytes,base,off,dummymap):
      if ins is None: #If the instruction was invalid, stop current disassembly
        break
      #print '0x%x:\t%s\t%s'%(ins.address,ins.mnemonic,ins.op_str)
      newins = translate_one(ins,None) #In this pass, the mapping is incomplete
      if newins is not None:
        currmap[ins.address] = len(newins)
        newoff+=len(newins) #Move our mapping's offset by the size of the new instructions
      else:
        currmap[ins.address] = len(ins.bytes)
        newoff+=len(ins.bytes) #Move our mapping's offset by the size of the original instruction
    if currmap != {}: #If we have inserted any entries into this mapping, append to our maplist
      #Add an instruction to the last patched instruction jumping to wherever the next instruction
      #would map to, since it isn't contiguous
      reroute = asm('jmp $+0x8f')
      last = max(currmap.keys())
      currmap[last]+=len(reroute)
      maplist.append(currmap)
      dummymap.update(currmap)
    '''
    while instoff < len(bytes):
      in_mapping = False
      for m in maplist:
        if base+instoff in m:
          in_mapping = True
          break
      if in_mapping:
        break
      insts = md.disasm(bytes[instoff:instoff+15],base+instoff)#longest x86/x64 instr is 15 bytes
      try:
        ins = insts.next()
        print "%s AND %s"%(base+instoff,ins.address)
        currmap[base+instoff] = newoff
        instoff+=len(ins.bytes) #Move instoff only as far as the next old instruction
        newins = translate_one(ins,None)#In this pass, the mapping is incomplete
        if newins is not None:
          newoff+=len(newins) #Move our mapping's offset further than instoff (size of NEW instructions)
        else:
          newoff+=len(ins.bytes)
      except StopIteration:
        newoff+=1 #Just move forward one byte
        instoff+=1
    if currmap != {}: #If we have inserted any entries into this mapping, append to our maplist
      maplist.append(currmap)
    '''
  offset = 0
  for m in maplist:
    for k in sorted(m.keys()):
      size = m[k]
      mapping[k] = offset
      offset+=size #Add the size of this instruction to the total offset
  #Now that the mapping is complete, we can add the mapping of the lookup function to the end
  #TODO: Perhaps it would be more efficient if we guaranteed the function to be aligned?
  global lookup_function_offset
  global mapping_offset
  lookup_function_offset = len(bytes)+base #Where we pretend it was in the old code (after the end)
  mapping_offset = len(bytes)+base+1 #Where we pretend the mapping was in the old code
  mapping[len(bytes)+base] = offset #Should be 1 after last instruction in new mapping
  #Don't yet know mapping offset; we must compute it
  lookup_size = len(get_lookup_code(base,len(bytes),offset,0x8f)) #TODO: Issue with mapping offset & size
  mapping[len(bytes)+base+1] = offset+lookup_size
  print 'lookup mapping %s:%s'%(hex(lookup_function_offset),hex(newoff+base))
  print 'mapping mapping %s:%s'%(hex(mapping_offset),hex(newoff+base+1))
  return mapping

def write_mapping(mapping,base,size):
  bytes = b''
  for addr in range(base,base+size):
    if addr in mapping:
      bytes+=struct.pack('<I',mapping[addr]) #Write our offset in little endian
    else:
      print 'No mapping for 0x%x'%addr
      bytes+=struct.pack('<I',0xffffffff) #Write an invalid offset if not in mapping
  print 'last address was 0x%x'%(base+size)
  return bytes

def gen_newcode(md,bytes,base,mapping):
  newbytes = ''
  bytemap = {}
  maplist = [] #This maplist maps addresses to patched instruction bytes instead of a new address
  dummymap = {}
  for off in range(0,len(bytes)):
    currmap = {}
    #print "[CODE] DOING OFFSET %s"%off
    for ins in brute_force_disasm(md,bytes,base,off,dummymap):
      if ins is None: #If the instruction was invalid, stop current disassembly
        break
      #print '0x%x:\t%s\t%s'%(ins.address,ins.mnemonic,ins.op_str)
      newins = translate_one(ins,mapping) #In this pass, the mapping is incomplete
      if newins is not None:
        tmps = md.disasm(newins,base+mapping[ins.address])
        print 'address: %x off: %x mapping[addr]: %x'%(ins.address,off,mapping[ins.address])
        for tmp in tmps:
          print '0x%x(0x%x):\t%s\t%s'%(tmp.address,ins.address,tmp.mnemonic,tmp.op_str)
        print '---'
        currmap[ins.address] = newins #Old address maps to these new instructions
      else:
        currmap[ins.address] = str(ins.bytes) #This instruction is unchanged, and its old address maps to it
    if currmap != {}: #If we have inserted any entries into this mapping, append to our maplist
      #Add an instruction to the last patched instruction jumping to wherever the next instruction
      #would map to, since it isn't contiguous
      last = max(currmap.keys())
      ins = md.disasm(bytes[last-base:(last-base+15)],last).next() #should always disassemble
      size = len(currmap[last]) #size of instructions we need to skip over
      target = last+len(ins.bytes) #address of where in the original code we would want to jmp to
      next_target = remap_target(last,mapping,target,size)
      reroute = asm('jmp $+'+next_target)
      if len(reroute) == 2: #Short encoding, which we do not want
        reroute+='\x90\x90\x90' #Add padding of 3 NOPs
      currmap[last]+=reroute #add bytes of unconditional jump
      maplist.append(currmap)
      dummymap.update(currmap)
  for m in maplist: #For each code mapping, in order of discovery
    for k in sorted(m.keys()): #For each original address to code, in order of original address
      newbytes+=m[k]
  print newbytes[0:10]
  '''
    insts = md.disasm(bytes[off:off+15],base+off)#longest possible x86/x64 instr is 15 bytes
    try:
      ins = insts.next()
      newins = translate_one(ins,mapping)#The mapping is now complete
      if newins is not None:
        #print '%s'%newins.encode('hex')
        tmps = md.disasm(newins,base+mapping[base+off])
        print 'address: %x off: %x mapping[base+off]: %x len(newbytes): %x '%(ins.address,off,mapping[base+off],len(newbytes))
        for tmp in tmps:
          print '0x%x(0x%x):\t%s\t%s'%(tmp.address,len(newbytes)+base,tmp.mnemonic,tmp.op_str)
        print '---'
        newbytes+=newins #newins is simply the bytes of an assembled instruction
      else:
        newbytes+=bytes[off]
    except StopIteration:
      newbytes+=bytes[off] #No change, just add byte
    '''
  #Append lookup function and then mapping to end of bytes
  newbytes+=get_lookup_code(base,len(bytes),mapping[lookup_function_offset],mapping[mapping_offset])
  newbytes+=write_mapping(mapping,base,len(bytes))
  return newbytes

def renable(fname):
  offs = size = addr = 0
  with open(fname,'rb') as f:
    elffile = ELFFile(f)
    relplt = None
    dynsym = None
    entry = elffile.header.e_entry #application entry point
    global get_pc_thunk
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
      if section.name == '.symtab':
        for sym in section.iter_symbols():
          if sym.name == '__x86.get_pc_thunk.bx':
            get_pc_thunk = sym.entry['st_value'] #Address of thunk
        #section.get_symbol_by_name('__x86.get_pc_thunk.bx')) #Apparently this is in a newer pyelftools
    plt['entries'] = {}
    if relplt is not None:
      for rel in relplt.iter_relocations():
        got_off = rel['r_offset'] #Get GOT offset address for this entry
        ds_ent = ELF32_R_SYM(rel['r_info']) #Get offset into dynamic symbol table
        name = dynsym.get_symbol(ds_ent).name #Get name of symbol
        plt['entries'][got_off] = name #Insert this mapping from GOT offset address to symbol name
    else:
        print 'binary does not contain plt'
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
        #maptext = write_mapping(mapping,base,len(bytes))
        #(mapping,newbytes) = translate_all(seg.data(),seg.header['p_vaddr'])
        #insts = md.disasm(newbytes[0x8048360-seg.header['p_vaddr']:0x8048441-seg.header['p_vaddr']],0x8048360)
        #The "mysterious" bytes between the previously patched instruction 
        #(originally at 0x804830b) are the remaining bytes from that jmp instruction!
        #So even though there was nothing between that jmp at the end of that plt entry
        #and the start of the next plt entry, now there are 4 bytes from the rest of the jmp.
        #This is a good example of why I need to take a different approach to generating the mapping.
        #insts = md.disasm(newbytes[0x80483af-seg.header['p_vaddr']:0x80483bf-seg.header['p_vaddr']],0x80483af)
        insts = md.disasm(newbytes,0x8048000)
        for ins in insts:
          print '0x%x:\t%s\t%s'%(ins.address,ins.mnemonic,ins.op_str)
        tmpdct = {hex(k): (lambda x:hex(x+seg.header['p_vaddr']))(v) for k,v in mapping.items()}
        keys = tmpdct.keys()
        keys.sort()
        output = ''
        for key in keys:
          output+='%s:%s '%(key,tmpdct[key])
        with open('newbytes','wb') as f2:
          f2.write(newbytes)
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
        lookup = get_lookup_code(base,len(bytes),mapping[lookup_function_offset],0x8f)
        print 'lookup w/unknown mapping %s'%len(lookup)
        insts = md.disasm(lookup,0x0)
	for ins in insts:
          print '0x%x:\t%s\t%s\t%s'%(ins.address,str(ins.bytes).encode('hex'),ins.mnemonic,ins.op_str)
        lookup = get_lookup_code(base,len(bytes),mapping[lookup_function_offset],mapping[mapping_offset])
        print 'lookup w/known mapping %s'%len(lookup)
        insts = md.disasm(lookup,0x0)
	for ins in insts:
          print '0x%x:\t%s\t%s\t%s'%(ins.address,str(ins.bytes).encode('hex'),ins.mnemonic,ins.op_str)
        if 0x80482b4 in mapping:
		print 'simplest only: _init at 0x%x'%mapping[0x80482b4]
        print 'entry point: %x'%mapping[entry]
          
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
    #renable(sys.argv[1])
    cProfile.run('renable(sys.argv[1])')
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
