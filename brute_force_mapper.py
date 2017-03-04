import brute_force_disassembler
import assembler

class BruteForceMapper(Mapper):
  ''' This mapper disassembled from every offset and includes a
      mapping for instructions at every byte offset in the code.
      To avoid duplicate code, when the disassembler encounters instructions
      it has encountered before, the mapper simply includes a jump instruction
      to link the current sequence to a previously mapped sequence.'''
  
  def __init__(self,arch,bytes,base,entry):
    self.disassembler = BruteForceDisassembler(arch)
    self.bytes = bytes
    self.base = base
    self.entry = entry

  def gen_mapping(self):
    print 'Generating mapping...'
    mapping = {}
    last = None #Last instruction disassembled
    reroute = assembler.asm('jmp $+0x8f') #Dummy jmp to imitate connecting jmp; we may not know dest yet
    for ins in self.disassembler.disasm(self.bytes,self.base):
      if ins is None and last is not None: # Encountered a previously disassembled instruction and have not redirected
        mapping[last.address] += len(reroute)
        last = None #If we have not found any more new instructions since our last redirect, don't redirect again
      else:
        last = ins #Remember the last disassembled instruction
        newins = translate_one(ins,None) #In this pass, the mapping is incomplete
        if newins is not None:
          mapping[ins.address] = len(newins)
        else:
          mapping[ins.address] = len(ins.bytes)
    global lookup_function_offset
    lookup_function_offset = 0 #Place lookup function at start of new text section
    lookup_size = len(get_lookup_code(self.base,len(self.bytes),0,0x8f)) #TODO: Issue with mapping offset & size
    offset = lookup_size
    if exec_only:
      global secondary_lookup_function_offset
      secondary_lookup_function_offset = offset
      secondary_lookup_size = len(get_secondary_lookup_code(self.base,len(self.bytes),offset,0x8f))
      offset += secondary_lookup_size
    for k in sorted(mapping.keys()):
      size = mapping[k]
      mapping[k] = offset
      offset+=size #Add the size of this instruction to the total offset
    #Now that the mapping is complete, we know the length of it
    global mapping_offset
    mapping_offset = len(self.bytes)+self.base #Where we pretend the mapping was in the old code
    if not write_so:
      global new_entry_off
      new_entry_off = offset #Set entry point to start of auxvec
      offset+=len(get_auxvec_code(0x8f))#Unknown entry addr here, but not needed b/c we just need len
    mapping[lookup_function_offset] = lookup_function_offset
    if exec_only:
      #This is a very low number and therefore will not be written out into the final mapping.
      #It is used to convey this offset for the second phase when generating code, specifically
      #for the use of remap_target.  Without setting this it always sets the target to 0x8f. Sigh.
      mapping[secondary_lookup_function_offset] = secondary_lookup_function_offset
    #Don't yet know mapping offset; we must compute it
    mapping[len(bytes)+self.base] = offset
    if not write_so:
      #For NOW, place the global data/function at the end of this because we can't necessarily fit
      #another section.  TODO: put this somewhere else
      global global_sysinfo
      global global_flag
      #The first time, sysinfo's and flag's location is unknown,
      #so they are wrong in the first call to get_global_lookup_code
      #However, the global_flag is moving to a TLS section, so it takes
      #up no space in the global lookup
      #global_flag = global_lookup + len(get_global_lookup_code())
      #popgm goes directly after the global lookup, and global_sysinfo directly after that.
      global popgm_offset
      popgm_offset = len(get_global_lookup_code())
      global_sysinfo = global_lookup + popgm_offset + len(write_popgm())
      #Now that this is set, the auxvec code should work
    return mapping

  def gen_newcode(self,mapping):
    print 'Generating new code...'
    newbytes = ''
    bytemap = {}
    last = None #Last instruction disassembled
    for ins in self.disassembler.disasm(self.bytes,self.base):
      if ins is None and last is not None: # Encountered a previously disassembled instruction and have not redirected
        target = last.address + len(last.bytes) #address of where in the original code we would want to jmp to
        next_target = remap_target(last.address, mapping, target, len(bytemap[last.address]) )
        reroute = assembler.asm( 'jmp $+%s'%(next_target) )
        if len(reroute) == 2: #Short encoding, which we do not want
          reroute+='\x90\x90\x90' #Add padding of 3 NOPs
        bytemap[last.address] += reroute
        last = None
      else:
        last = ins #Remember the last disassembled instruction
        newins = translate_one(ins,mapping) #In this pass, the mapping is incomplete
        if newins is not None:
          bytemap[ins.address] = newins #Old address maps to these new instructions
        else:
          bytemap[ins.address] = str(ins.bytes) #This instruction is unchanged, and its old address maps to it
    #Add the lookup function as the first thing in the new text section
    newbytes+=get_lookup_code(self.base,len(self.bytes),lookup_function_offset,mapping[mapping_offset])
    if exec_only:
      newbytes += get_secondary_lookup_code(self.base,len(self.bytes),secondary_lookup_function_offset,mapping[mapping_offset])
    for k in sorted(bytemap.keys()): #For each original address to code, in order of original address
      newbytes+=bytemap[k]
    if not write_so:
      newbytes+=get_auxvec_code(mapping[self.entry])
    #Append mapping to end of bytes
    newbytes+=write_mapping(mapping,self.base,len(self.bytes))
    return newbytes
