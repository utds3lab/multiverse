from x64_assembler import asm,cache,metacache
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
import struct
import re
from translator import Translator

class X64Translator(Translator):

  def __init__(self,before_callback,context):
    self.before_inst_callback = before_callback
    self.context = context
    self.memory_ref_string = re.compile(u'^qword ptr \[(?P<rip>0x[0-9a-z]+) \+ (?P<offset>0x[0-9a-z]+)\]$')
    self.rip_with_offset = re.compile(u'\[rip(?: (?P<offset>[\+\-] [0x]?[0-9a-z]+))?\]') #Apparently the hex prefix is optional if the number is...unambiguous?
    # Pre-populate this instruction in the metacache so we can avoid rewriting variations of it
    metacache['        lea rbx,[rip]'] = 3
    metacache['    lea rbx,[rip]'] = 3
    #From Brian's Static_phase.py
    self.JCC = ['jo','jno','js','jns','je','jz','jne','jnz','jb','jnae',
      'jc','jnb','jae','jnc','jbe','jna','ja','jnbe','jl','jnge','jge',
      'jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jrcxz','jecxz']

  def replace_rip(self,ins,mapping,newlen):
        code = b''
        # In the main binary, we technically do not need to use rip;
        # since we know the location our main binary code will be at,
        # we can replace it with an absolute address.  HOWEVER, if we want
        # to support position-independent main binaries, and if we don't
        # want to have to re-assemble any instructions that our assembler
        # cannot currently handle correctly (such as ljmp), then it is better
        # to simply replace rip in the same way as in shared objects.
        #
        # For shared objects we *need* to use rip, but calculate
        # (rip - (newbase + after new instruction address)) + address after old instruction
        # or (rip + ( (address after old instruction) - (newbase + after new instruction address) ) )
        # The goal is to compute the value rip WOULD have had if the original binary were run, and replace
        # rip with that value, derived from the NEW value in rip...
        match = self.rip_with_offset.search(ins.op_str) #TODO: all this new stuff with the match and then the assembler optimization
        if mapping is not None:
          #print 'rewriting %s instruction with rip: %s %s' % (ins.mnemonic,ins.mnemonic,ins.op_str) 
          oldoffset = 0 #Assume at first that there is no offset from rip
          if match.group('offset') != None:
            #print 'match on offset: %s' % match.group('offset')
            oldoffset = int(match.group('offset'), 16)
          oldaddr = ins.address + len(ins.bytes)
          # For completely rewritten instructions, the new length will indeed change, because the original instruction
          # may be rewritten into multiple instructions, with potentially many instructions inserted before the one
          # that references rip.  Because an instruction referring to rip has it pointing after that instruction, we need
          # the length of all code preceding it and then the length of the new instruction referencing rip to know the 
          # *real* new address.  Then we can determine the offset between them and add the old offset, thereby giving our new offset.
          # All instructions may potentially have code inserted before them, so we will always need this new length.
          newaddr = mapping[ins.address] + newlen
          newoffset = (oldaddr - (self.context.newbase + newaddr)) + oldoffset
          newopstr = ''
          # If the new offset cannot be encoded in 4 bytes, replace it with a placeholder
          if newoffset <= -0x80000000 or newoffset >= 0x7fffffff:
            print 'WARNING: unencodable offset for instruction @ 0x%x: %x' % (ins.address,newoffset)
            newoffset = -0x7faddead
          # Check whether it's negative so we can prefix with 0x even with negative numbers
          if newoffset < 0:
            newopstr = self.rip_with_offset.sub('[rip - 0x%x]' % -newoffset, ins.op_str)
          else:
            newopstr = self.rip_with_offset.sub('[rip + 0x%x]' % newoffset, ins.op_str)
          #print 'Old offset: 0x%x / Old address: 0x%x / New address: 0x%x / New base: 0x%x' % (oldoffset,oldaddr,newaddr,self.context.newbase)
          #print 'New instruction: %s %s' % (ins.mnemonic,newopstr)
          return newopstr
        else:
          #Placeholder until we know the new instruction location
          newopstr = self.rip_with_offset.sub('[rip]', ins.op_str)
          #print 'rewriting %s instruction with rip: %s %s' % (ins.mnemonic,ins.mnemonic,ins.op_str) 
          #print 'assembling %s %s' % (ins.mnemonic, newopstr)
          #print 'instruction is %s' % str(ins.bytes[:-4] + (b'\0'*4)).encode('hex')
          newins = '%s %s' % (ins.mnemonic, newopstr)
          # Pre-populate cache with version of this instruction with NO offset; this means we never have to call assembler for this instruction.
          # The assembler can just replace the offset, which we assume is the last 4 bytes in the instruction
          if newins not in cache:
            # Only add to the cache ONCE.  If you keep adding to the cache, some instructions have prefixes that ALTER the base instruction length
            # for that instruction with no offset.  Therefore, if another instruction comes along with the same mnemonic and opstring, but containing
            # a different number of garbage prefixes before it, then the length of these instructions fluctuates, throwing off all the careful alignment
            # required for mapping these instructions.  Due to these garbage prefixes, some instructions may increase by a few bytes and semantics could
            # potentially, theoretically be altered, but this could be solved with a better assembler or disassembler.
            # ---
            # The displacement size and offset are not easily obtainable in the current version of capstone, so this requires a customized version that
            # provides access to this data.  With this, we can determine exactly the position of the displacement and replace it
            disp_size = ins._detail.arch.x86.encoding.disp_size
            disp_offset = ins._detail.arch.x86.encoding.disp_offset
            # We will only automatically replace 4-byte displacements, because smaller ones will very likely not fit the new displacement, and 4-byte
            # displacements are much more common.  This means we will need to re-assemble any instructions that do not have a 4-byte displacement, however.
            if disp_size == 4:
              metacache[newins] = disp_offset # Save displacement offset for assembler
              # Populate version in cache with the instruction with a displacement of all 0s.  Leave the immediate value (if there is one) intact.
              cache[newins] = ins.bytes[:disp_offset] + (b'\0'*4) + ins.bytes[disp_offset+disp_size:]
            else:
              # TODO: Changing the instruction to use a larger displacement WILL change the instruction length, and thus WILL result in an incorrect new
              # displacement as we calculate it now.  This needs to be fixed to use the correct new displacement as it would be calculated after knowing
              # the new instruction length.
              print 'WARNING: instruction %s has small displacement: %d'%(newins,disp_size)
          return newopstr

  def translate_one(self,ins,mapping):
    if ins.mnemonic in ['call','jmp']: #Unconditional jump
      return self.translate_uncond(ins,mapping)
    elif ins.mnemonic in self.JCC: #Conditional jump
      return self.translate_cond(ins,mapping)
    elif ins.mnemonic == 'ret':
      return self.translate_ret(ins,mapping)
    elif ins.mnemonic in ['retn','retf','repz']: #I think retn is not used in Capstone
      #print 'WARNING: unimplemented %s %s'%(ins.mnemonic,ins.op_str)
      return '\xf4\xf4\xf4\xf4' #Create obvious cluster of hlt instructions
    else: #Any other instruction
      inserted = self.before_inst_callback(ins)
      #Even for non-control-flow instructions, we need to replace all references to rip
      #with the address pointing directly after the instruction.
      #TODO: This will NOT work for shared libraries or any PIC, because it depends on
      #knowing the static instruction address.  For all shared objects, we would need to
      #subtract off the offset between the original and new text; as long as the offset is
      #fixed, then we should be able to just precompute that offset, without it being affected
      #by the position of the .so code
      #TODO: abandon rewriting ljmp instructions for now because the assembler doesn't like them
      #and we haven't been rewriting their destinations anyway; if they *are* used, they were already
      #broken before this 
      #TODO: I have also abandoned rewriting the following instructions because I can't get it to
      #re-assemble with the current assembler:
      #  fstp
      #  fldenv
      #  fld
      #TODO: Since I am now doing a crazy optimization in which I use the original instruction's bytes
      #and only change the last 4 bytes (the offset), I should actually be able to support these incompatible
      #instructions by saving their original bytes in the assembler cache and therefore never actually sending
      #the disassembled instruction to the assembler at all.
      incompatible = ['ljmp', 'fstp', 'fldenv', 'fld', 'fbld']
      if 'rip' in ins.op_str:# and (ins.mnemonic not in incompatible):
        '''asm1 = asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping) ) )
        asm2 = asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,None) ) )
        if len(asm1) != len(asm2):
          print '%s %s @ 0x%x LENGTH FAIL1: %s vs %s' % (ins.mnemonic, ins.op_str, ins.address, str(asm1).encode('hex'), str(asm2).encode('hex') )
          newone = len( asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping) ) ) )
          oldone = len( asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,None) ) ) )
          print '%d vs %d, %d vs %d' % (newone,oldone,len(asm1),len(asm2))'''
        code = b''
        if inserted is not None:
          code = asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping,len(inserted) + len(ins.bytes) ) ) )
          code = inserted + code
        else:
          code = asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping,len(ins.bytes) ) ) )
        return code
      else:
	'''if 'rip' in ins.op_str and (ins.mnemonic in incompatible):
          print 'NOT rewriting %s instruction with rip: %s %s' % (ins.mnemonic,ins.mnemonic,ins.op_str) 
        if ins.mnemonic == 'ljmp':
          print 'WARNING: unhandled %s %s @ %x'%(ins.mnemonic,ins.op_str,ins.address)'''
        if inserted is not None:
          return inserted + str(ins.bytes)
      return None #No translation needs to be done

  def translate_ret(self,ins,mapping):
    '''
    mov [esp-28], eax	;save old eax value
    pop eax		;pop address from stack from which we will get destination
    call $+%s		;call lookup function
    mov [esp-4], eax	;save new eax value (destination mapping)
    mov eax, [esp-32]	;restore old eax value (the pop has shifted our stack so we must look at 28+4=32)
    jmp [esp-4]		;jmp/call to new address
    '''
    template_before = '''
    mov [rsp-56], rax
    pop rax
    '''
    template_after = '''
    call $+%s
    %s
    mov [rsp-8], rax
    mov rax, [rsp-%d]
    jmp [rsp-8]
    '''
    self.context.stat['ret']+=1
    code = b''
    inserted = self.before_inst_callback(ins)
    if inserted is not None:
      code += inserted
    # Since thunks do not need to be used for 64-bit code, there is no specific
    # place we need to treat as a special case.  It is unlikely that code will
    # try to use the pushed return address to obtain the instruction pointer 
    # (after all, it can just access it directly!), but should it TRY to do this,
    # the program will crash!  Thus the no_pic optimization is a heuristic that
    # won't work for some code (in this case only very unusual code?)
    if self.context.no_pic: # and ins.address != self.context.get_pc_thunk + 3:
      #Perform a normal return UNLESS this is the ret for the thunk.
      #Currently its position is hardcoded as three bytes after the thunk entry.
      code = asm( 'ret %s'%ins.op_str )
    else:
      code = asm(template_before)
      size = len(code)
      lookup_target = b''
      if self.context.exec_only:
        #Special lookup for not rewriting arguments when going outside new main text address space
        lookup_target = self.remap_target(ins.address,mapping,self.context.secondary_lookup_function_offset,size)
      else:
        lookup_target = self.remap_target(ins.address,mapping,self.context.lookup_function_offset,size)
      if ins.op_str == '':
        code+=asm(template_after%(lookup_target,'',64)) #64 because of the value we popped
      else: #For ret instructions that pop imm16 bytes from the stack, add that many bytes to esp
        pop_amt = int(ins.op_str,16) #We need to retrieve the right eax value from where we saved it
        code+=asm(template_after%(lookup_target,'add rsp,%d'%pop_amt,64+pop_amt))
    return code

  def translate_cond(self,ins,mapping):
    self.context.stat['jcc']+=1
    patched = b''
    inserted = self.before_inst_callback(ins)
    if inserted is not None:
      patched += inserted
    if ins.mnemonic in ['jrcxz','jecxz']: #These instructions have no long encoding (and jcxz is not allowed in 64-bit)
      jrcxz_template = '''
      test rcx,rcx
      '''
      jecxz_template = '''
      test ecx,ecx
      '''
      target = ins.operands[0].imm # int(ins.op_str,16) The destination of this instruction
      #newtarget = remap_target(ins.address,mapping,target,0)
      if ins.mnemonic == 'jrcxz':
        patched+=asm(jrcxz_template)
      else:
        patched+=asm(jecxz_template)
      newtarget = self.remap_target(ins.address,mapping,target,len(patched))
      #print 'want %s, but have %s instead'%(remap_target(ins.address,mapping,target,len(patched)), newtarget)
      #Apparently the offset for jcxz and jecxz instructions may have been wrong?  How did it work before?
      patched += asm('jz $+%s'%newtarget)
      #print 'code length: %d'%len(patched)
      
      #TODO: some instructions encode to 6 bytes, some to 5, some to 2.  How do we know which?
      #For example, for CALL, it seems to only be 5 or 2 depending on offset.
      #But for jg, it can be 2 or 6 depending on offset, I think because it has a 2-byte opcode.
      #while len(patched) < 6: #Short encoding, which we do not want
      #  patched+='\x90' #Add padding of NOPs
      #The previous commented out code wouldn't even WORK now, since we insert another instruction
      #at the MINIMUM.  I'm amazed the jcxz/jecxz code even worked at all before
    else:
      target = ins.operands[0].imm # int(ins.op_str,16) The destination of this instruction
      newtarget = self.remap_target(ins.address,mapping,target,len(patched))
      patched+=asm(ins.mnemonic + ' $+' + newtarget)
      #TODO: some instructions encode to 6 bytes, some to 5, some to 2.  How do we know which?
      #For example, for CALL, it seems to only be 5 or 2 depending on offset.
      #But for jg, it can be 2 or 6 depending on offset, I think because it has a 2-byte opcode.
      #while len(patched) < 6: #Short encoding, which we do not want
      #  patched+='\x90' #Add padding of NOPs
    return patched
  
  def translate_uncond(self,ins,mapping):
    op = ins.operands[0] #Get operand
    if op.type == X86_OP_REG: # e.g. call eax or jmp ebx
      target = ins.reg_name(op.reg)
      return self.get_indirect_uncond_code(ins,mapping,target)
    elif op.type == X86_OP_MEM: # e.g. call [eax + ecx*4 + 0xcafebabe] or jmp [ebx+ecx]
      target = ins.op_str
      return self.get_indirect_uncond_code(ins,mapping,target)
    elif op.type == X86_OP_IMM: # e.g. call 0xdeadbeef or jmp 0xcafebada
      target = op.imm
      code = b''
      inserted = self.before_inst_callback(ins)
      if inserted is not None:
        code += inserted
      # Again, there is no thunk special case for 64-bit code
      if self.context.no_pic: # and target != self.context.get_pc_thunk:
        #push nothing if no_pic UNLESS it's the thunk
        #We only support DIRECT calls to the thunk
        if ins.mnemonic == 'call':
          self.context.stat['dircall']+=1
        else:
          self.context.stat['dirjmp']+=1
      elif ins.mnemonic == 'call': #If it's a call, push the original address of the next instruction
        self.context.stat['dircall']+=1
        exec_call = '''
        push %s
        '''
        so_call = '''
        push rbx
        lea rbx,[rip - 0x%x]
        xchg rbx,[rsp]
        '''
        if self.context.write_so:
          if mapping is not None:
            # 8 is the length of push rbx;lea rbx,[rip-%s]
            code += asm(so_call%( (self.context.newbase+(mapping[ins.address]+8)) - (ins.address+len(ins.bytes)) ) )
          else:
            code += asm(so_call%( (self.context.newbase) - (ins.address+len(ins.bytes)) ) )
        else:
          code += asm(exec_call%(ins.address+len(ins.bytes)))
      else:
        self.context.stat['dirjmp']+=1
      newtarget = self.remap_target(ins.address,mapping,target,len(code))
      #print "(pre)new length: %s"%len(callback_code)
      #print "target: %s"%hex(target)
      #print "newtarget: %s"%newtarget
      # Again, there is no thunk special case for 64-bit code
      if self.context.no_pic: # and target != self.context.get_pc_thunk:
        code += asm( '%s $+%s'%(ins.mnemonic,newtarget) )
      else:
        patched = asm('jmp $+%s'%newtarget)
        if len(patched) == 2: #Short encoding, which we do not want
          patched+='\x90\x90\x90' #Add padding of 3 NOPs
        code += patched
      #print "new length: %s"%len(callback_code+patched)
      return code
    return None
  
  def get_indirect_uncond_code(self,ins,mapping,target):
    #Commented assembly
    '''
    mov [esp-28], eax	;save old eax value (very far above the stack because of future push/call)
    mov eax, %s		;read location in memory from which we will get destination
    %s			;if a call, we push return address here
    call $+%s		;call lookup function
    mov [esp-4], eax	;save new eax value (destination mapping)
    mov eax, [esp-%s]	;restore old eax value (offset depends on whether return address pushed)
    jmp [esp-4]		;jmp to new address
    '''
    #If the argument is an offset from rip, then we must change the reference to rip.  Any rip-relative
    #addressing is destroyed because all the offsets are completely different; we need the 
    #original address that rip WOULD have pointed to, so we must replace any references to it.
    template_before = '''
    mov [rsp-64], rax
    mov rax, %s
    %s
    '''
    exec_call = '''
    push %s
    '''
    so_call_before = '''
    push rbx
    '''
    so_call_after = '''
    lea rbx,[rip - 0x%x]
    xchg rbx,[rsp]
    '''
    template_after = '''
    call $+%s
    mov [rsp-8], rax
    mov rax, [rsp-%s]
    jmp [rsp-8]
    '''
    template_nopic = '''
    call $+%s
    mov [rsp-8], rax
    mov rax, [rsp-%s]
    %s [rsp-8]
    '''
    #TODO: This is somehow still the bottleneck, so this needs to be optimized
    code = b''
    if self.context.exec_only:
      code += self.get_remap_callbacks_code(ins.address,mapping,target)
    #NOTE: user instrumentation code comes after callbacks code.  No particular reason to put it either way,
    #other than perhaps consistency, but for now this is easier.
    inserted = self.before_inst_callback(ins)
    if inserted is not None:
      code += inserted
    #Replace references to rip with the original address after this instruction so that we
    #can look up the new address using the original
    if 'rip' in target:
      '''if len( asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping) ) ) ) != len( asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,None) ) ) ):
        print '%s %s @ 0x%x LENGTH FAIL2: %s vs %s' % (ins.mnemonic, ins.op_str, ins.address, str(asm('%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping) ))).encode('hex'), str(asm('%s %s' % (ins.mnemonic, self.replace_rip(ins,None)) )).encode('hex') )
        newone = len( asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,mapping) ) ) )
        oldone = len( asm( '%s %s' % (ins.mnemonic, self.replace_rip(ins,None) ) ) )
        print '%d vs %d, %s' % (newone,oldone,newone == oldone)'''
      # The new "instruction length" is the length of all preceding code, plus the instructions up through the one referencing rip
      target = self.replace_rip(ins,mapping,len(code) + len(asm('mov [rsp-64],rax\nmov rax,[rip]')) )
    if self.context.no_pic:
      if ins.mnemonic == 'call':
        self.context.stat['indcall']+=1
      else:
        self.context.stat['indjmp']+=1
      code += asm( template_before%(target,'') )
    elif ins.mnemonic == 'call':
      self.context.stat['indcall']+=1
      if self.context.write_so:
        code += asm( template_before%(target,so_call_before) )
        if mapping is not None:
          # 7 is the length of the lea rbx,[rip-%s] instruction, which needs to be added to the length of the code preceding where we access RIP
          code += asm(so_call_after%( (mapping[ins.address]+len(code)+7+self.context.newbase) - (ins.address+len(ins.bytes)) ) )
        else:
          code += asm(so_call_after%( (0x8f+self.context.newbase) - (ins.address+len(ins.bytes)) ) )
      else:
        code += asm(template_before%(target,exec_call%(ins.address+len(ins.bytes)) ))
    else:
      self.context.stat['indjmp']+=1
      code += asm(template_before%(target,''))
    size = len(code)
    lookup_target = self.remap_target(ins.address,mapping,self.context.lookup_function_offset,size)
    #Always transform an unconditional control transfer to a jmp, but
    #for a call, insert a push instruction to push the original return address on the stack.
    #At runtime, our rewritten ret will look up the right address to return to and jmp there.
    #If we push a value on the stack, we have to store even FURTHER away from the stack.
    #Note that calling the lookup function can move the stack pointer temporarily up to
    #20 bytes, which will obliterate anything stored too close to the stack pointer.  That, plus
    #the return value we push on the stack, means we need to put it at least 28 bytes away.
    if self.context.no_pic:
      #Change target to secondary lookup function instead
      lookup_target = self.remap_target(ins.address,mapping,self.context.secondary_lookup_function_offset,size)
      code += asm( template_nopic%(lookup_target,64,ins.mnemonic) )
    elif ins.mnemonic == 'call':
      code += asm(template_after%(lookup_target,56))
    else:  
      code += asm(template_after%(lookup_target,64))
    return code
  
  def get_remap_callbacks_code(self,insaddr,mapping,target):
    '''Checks whether the target destination (expressed as the opcode string from a jmp/call instruction)
       is in the got, then checks if it matches a function with callbacks.  It then rewrites the
       addresses if necessary.  This will *probably* always be from jmp instructions in the PLT.
       NOTE: This assumes it does not have any code inserted before it, and that it comprises
       the first special instructions inserted for an instruction.'''
    if self.memory_ref_string.match(target):
      match = self.memory_ref_string.match(target)
      #Add address of instruction after this one and the offset to get destination
      address = int(match.group('rip'), 16) + int(match.group('offset'), 16)
      if address in self.context.plt['entries']:
        if self.context.plt['entries'][address] in self.context.callbacks:
          print 'Found library call with callbacks: %s'%self.context.plt['entries'][address]
          return self.get_callback_code( insaddr, mapping, self.context.callbacks[self.context.plt['entries'][address]] )
    return b''
  
  def get_callback_code(self,address,mapping,cbargs):
    '''Remaps each callback argument based on index.  cbargs is an array of argument indices
       that let us know which argument (a register in x64) we must rewrite.
       We insert code for each we must rewrite.'''
    arg_registers = ['rdi','rsi','rdx','rcx','r8','r9'] #Order of arguments in x86-64
    callback_template_before = '''
    mov rax, %s
    '''
    callback_template_after = '''
    call $+%s
    mov %s, rax
    '''
    code = asm('push rax') #Save rax, use to hold callback address
    for ind in cbargs:
      #Move value in register for that argument to rax
      cb_before = callback_template_before%( arg_registers[ind] )
      code += asm(cb_before) #Assemble this part first so we will know the offset to the lookup function
      size = len(code)
      #Use secondary lookup function so it won't try to rewrite arguments if the callback is outside the main binary
      lookup_target = self.remap_target( address, mapping, self.context.secondary_lookup_function_offset, size )
      cb_after = callback_template_after%( lookup_target, arg_registers[ind] )
      code += asm(cb_after) #Save the new address over the original
    code += asm('pop rax') #Restore rax
    return code
  
  def in_plt(self,target):
    return target in range(self.context.plt['addr'],self.context.plt['addr']+self.context.plt['size'])
  
  '''def get_plt_entry(self,target):
    #It seems that an elf does not directly give a mapping from each entry in the plt.
    #Instead, it maps from the got entries instead, making it unclear exactly where objdump
    #gets the information.  For our purposes, since all the entries in the plt jump to the got
    #entry, we can read the destination address from the jmp instruction.
    #TODO: ensure works for x64
    offset = target - self.context.plt['addr'] #Get the offset into the plt
    #TODO: The following assumes an absolute jmp, whereas I believe it is a rip-relative jmp in x64
    dest = self.context.plt['data'][offset+2:offset+2+4] #Get the four bytes of the GOT address
    dest = struct.unpack('<I',dest)[0] #Convert to integer, respecting byte endianness
    if dest in self.context.plt['entries']:
      return self.context.plt['entries'][dest] #If there is an entry, return that; the name of the function
    return None #Some entries may be a jump to the start of the plt (no entry)
'''
  
  def remap_target(self,addr,mapping,target,offs): #Only works for statically identifiable targets
    newtarget = '0x8f'
    if mapping is not None and target in mapping:#Second pass, known mapping
      newtarget = mapping[target]-(mapping[addr]+offs) #Offset from curr location in mapping
      newtarget = hex(newtarget)
      #print "original target: %s"%hex(target)
      #print "%s-(%s+%s) = %s"%(hex(mapping[target]),hex(mapping[addr]),hex(offs),newtarget)
    return newtarget
