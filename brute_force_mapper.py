import struct
from mapper import Mapper
from brute_force_disassembler import BruteForceDisassembler

class BruteForceMapper(Mapper):
  ''' This mapper disassembled from every offset and includes a
      mapping for instructions at every byte offset in the code.
      To avoid duplicate code, when the disassembler encounters instructions
      it has encountered before, the mapper simply includes a jump instruction
      to link the current sequence to a previously mapped sequence.'''
  
  def __init__(self,arch,bytes,base,entry,context):
    self.disassembler = BruteForceDisassembler(arch)
    self.bytes = bytes
    self.base = base
    self.entry = entry
    self.context = context
    if arch == 'x86':
      #NOTE: We are currently NOT supporting instrumentation because we are passing
      #None to the translator.  TODO: Add back instrumentation after everything gets
      #working again, and make instrumentation feel more organized
      from x86_translator import X86Translator
      from x86_runtime import X86Runtime
      self.translator = X86Translator((lambda x: None),self.context)
      self.runtime = X86Runtime(self.context)
      global assembler
      import x86_assembler as assembler
    elif arch == 'x86-64':
      from x64_translator import X64Translator
      from x64_runtime import X64Runtime
      self.translator = X64Translator((lambda x: None),self.context)
      self.runtime = X64Runtime(self.context)
      global assembler
      import x64_assembler as assembler
    else:
      raise NotImplementedError( 'Architecture %s is not supported'%arch )

  def gen_mapping(self):
    print 'Generating mapping...'
    mapping = {}
    maplist = []
    currmap = {}
    last = None #Last instruction disassembled
    reroute = assembler.asm('jmp $+0x8f') #Dummy jmp to imitate connecting jmp; we may not know dest yet
    for ins in self.disassembler.disasm(self.bytes,self.base):
      if ins is None and last is not None: # Encountered a previously disassembled instruction and have not redirected
        currmap[last.address] += len(reroute)
        last = None #If we have not found any more new instructions since our last redirect, don't redirect again
        maplist.append(currmap)
        currmap = {}
      elif ins is not None:
        last = ins #Remember the last disassembled instruction
        newins = self.translator.translate_one(ins,None) #In this pass, the mapping is incomplete
        if newins is not None:
          currmap[ins.address] = len(newins)
        else:
          currmap[ins.address] = len(ins.bytes)
    self.context.lookup_function_offset = 0 #Place lookup function at start of new text section
    lookup_size = len(self.runtime.get_lookup_code(self.base,len(self.bytes),0,0x8f)) #TODO: Issue with mapping offset & size
    offset = lookup_size
    if self.context.exec_only:
      self.context.secondary_lookup_function_offset = offset
      secondary_lookup_size = len(self.runtime.get_secondary_lookup_code(self.base,len(self.bytes),offset,0x8f))
      offset += secondary_lookup_size
    for m in maplist:
      for k in sorted(m.keys()):
        size = m[k]
        mapping[k] = offset
        offset+=size #Add the size of this instruction to the total offset
    self.metamaplist = maplist
    #Now that the mapping is complete, we know the length of it
    self.context.mapping_offset = len(self.bytes)+self.base #Where we pretend the mapping was in the old code
    if not self.context.write_so:
      self.context.new_entry_off = offset #Set entry point to start of auxvec
      offset+=len(self.runtime.get_auxvec_code(0x8f))#Unknown entry addr here, but not needed b/c we just need len
    mapping[self.context.lookup_function_offset] = self.context.lookup_function_offset
    if self.context.exec_only:
      #This is a very low number and therefore will not be written out into the final mapping.
      #It is used to convey this offset for the second phase when generating code, specifically
      #for the use of remap_target.  Without setting this it always sets the target to 0x8f. Sigh.
      mapping[self.context.secondary_lookup_function_offset] = self.context.secondary_lookup_function_offset
    #Don't yet know mapping offset; we must compute it
    mapping[len(self.bytes)+self.base] = offset
    print 'final offset for mapping is: 0x%x' % offset
    if not self.context.write_so:
      #For NOW, place the global data/function at the end of this because we can't necessarily fit
      #another section.  TODO: put this somewhere else
      #The first time, sysinfo's and flag's location is unknown,
      #so they are wrong in the first call to get_global_lookup_code
      #However, the global_flag is moving to a TLS section, so it takes
      #up no space in the global lookup
      #global_flag = global_lookup + len(get_global_lookup_code())
      #popgm goes directly after the global lookup, and global_sysinfo directly after that.
      self.context.popgm_offset = len(self.runtime.get_global_lookup_code())
      self.context.global_sysinfo = self.context.global_lookup + self.context.popgm_offset + len(self.runtime.get_popgm_code())
      #Now that this is set, the auxvec code should work
    return mapping

  def gen_newcode(self,mapping):
    print 'Generating new code...'
    newbytes = ''
    bytemap = {}
    maplist = []
    last = None #Last instruction disassembled
    for ins in self.disassembler.disasm(self.bytes,self.base):
      if ins is None and last is not None: # Encountered a previously disassembled instruction and have not redirected
        target = last.address + len(last.bytes) #address of where in the original code we would want to jmp to
        next_target = self.translator.remap_target(last.address, mapping, target, len(bytemap[last.address]) )
        reroute = assembler.asm( 'jmp $+%s'%(next_target) )
        #Maximum relative displacement is 32 for x86 and x64, so this works for both platforms
        if len(reroute) == 2: #Short encoding, which we do not want
          reroute+='\x90\x90\x90' #Add padding of 3 NOPs
        bytemap[last.address] += reroute
        last = None
        maplist.append(bytemap)
        bytemap = {}
      elif ins is not None:
        last = ins
        newins = self.translator.translate_one(ins,mapping) #In this pass, the mapping is incomplete
        if newins is not None:
          bytemap[ins.address] = newins #Old address maps to these new instructions
        else:
          bytemap[ins.address] = str(ins.bytes) #This instruction is unchanged, and its old address maps to it
    #Add the lookup function as the first thing in the new text section
    newbytes+=self.runtime.get_lookup_code(self.base,len(self.bytes),self.context.lookup_function_offset,mapping[self.context.mapping_offset])
    if self.context.exec_only:
      newbytes += self.runtime.get_secondary_lookup_code(self.base,len(self.bytes),self.context.secondary_lookup_function_offset,mapping[self.context.mapping_offset])
    count = 0
    for m in maplist:
      for k in sorted(m.keys()): #For each original address to code, in order of original address
        newbytes+=m[k]
        for otherm in self.metamaplist:
          if k in otherm:
            if otherm[k] != len(m[k]): #ALERT!  ALERT!  LENGTH MISMATCH!
              print 'ALERT!  MISMATCH: 0x%s: %s vs %s' % ( hex(k),hex(otherm[k]),hex(len(m[k])) )
    if not self.context.write_so:
      newbytes+=self.runtime.get_auxvec_code(mapping[self.entry])
    print 'mapping is being placed at offset: 0x%x' % len(newbytes)
    #Append mapping to end of bytes
    newbytes+=self.write_mapping(mapping,self.base,len(self.bytes))
    return newbytes

  def write_mapping(self,mapping,base,size):
    bytes = b''
    for addr in range(base,base+size):
      if addr in mapping:
        if addr < 10:
          print 'offset for 0x%x: 0x%x' % (addr, mapping[addr])
        bytes+=struct.pack('<I',mapping[addr]) #Write our offset in little endian
      else:
        #print 'No mapping for 0x%x'%addr
        bytes+=struct.pack('<I',0xffffffff) #Write an invalid offset if not in mapping
    print 'last address in mapping was 0x%x'%(base+size)
    return bytes
