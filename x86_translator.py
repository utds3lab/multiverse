from assembler import asm
import struct

class X86Translator(Translator):

  def __init__(self,before_callback,context):
    self.before_inst_callback = before_callback
    self.context = context
    self.memory_ref_string = re.compile(u'^dword ptr \[(?P<address>0x[0-9a-z]+)\]$')

  def translate_one(self,ins,mapping):
    if ins.mnemonic in ['call','jmp']: #Unconditional jump
      return translate_uncond(ins,mapping)
    elif ins.mnemonic in JCC: #Conditional jump
      return translate_cond(ins,mapping)
    elif ins.mnemonic == 'ret':
      return translate_ret(ins,mapping)
    elif ins.mnemonic in ['retn','retf','repz']: #I think retn is not used in Capstone
      #print 'WARNING: unimplemented %s %s'%(ins.mnemonic,ins.op_str)
      return '\xf4\xf4\xf4\xf4' #Create obvious cluster of hlt instructions
    else: #Any other instruction
      inserted = self.before_inst_callback(ins)
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
    mov [esp-28], eax
    pop eax
    '''
    template_after = '''
    call $+%s
    %s
    mov [esp-4], eax
    mov eax, [esp-%d]
    jmp [esp-4]
    '''
    self.context.stat['ret']+=1
    code = b''
    inserted = self.before_inst_callback(ins)
    if inserted is not None:
      code += inserted
    if self.context.no_pic and ins.address != self.context.get_pc_thunk + 3:
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
        code+=asm(template_after%(lookup_target,'',32)) #32 because of the value we popped
      else: #For ret instructions that pop imm16 bytes from the stack, add that many bytes to esp
        pop_amt = int(ins.op_str,16) #We need to retrieve the right eax value from where we saved it
        code+=asm(template_after%(lookup_target,'add esp,%d'%pop_amt,32+pop_amt))
    return code

  def translate_cond(self,ins,mapping):
    self.context.stat['jcc']+=1
    patched = b''
    inserted = self.before_inst_callback(ins)
    if inserted is not None:
      patched += inserted
    if ins.mnemonic in ['jcxz','jecxz']: #These instructions have no long encoding
      jcxz_template = '''
      test cx,cx
      '''
      jecxz_template = '''
      test ecx,ecx
      '''
      target = ins.operands[0].imm # int(ins.op_str,16) The destination of this instruction
      #newtarget = remap_target(ins.address,mapping,target,0)
      if ins.mnemonic == 'jcxz':
        patched+=asm(jcxz_template)
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
      if self.context.no_pic and target != self.context.get_pc_thunk:
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
        so_call_before = '''
        push ebx
        call $+5
        '''
        so_call_after = '''
        pop ebx
        sub ebx,%s
        xchg ebx,[esp]
        '''
        if write_so:
          code += asm(so_call_before)
          if mapping is not None:
            # Note that if somehow newbase is a very small value we could have problems with the small
            # encoding of sub.  This could result in different lengths between the mapping and code gen phases
            code += asm(so_call_after%( (newbase+(mapping[ins.address]+len(code))) - (ins.address+len(ins.bytes)) ) )
          else:
            code += asm(so_call_after%( (newbase) - (ins.address+len(ins.bytes)) ) )
        else:
          code += asm(exec_call%(ins.address+len(ins.bytes)))
      else:
        self.context.stat['dirjmp']+=1
      newtarget = self.context.remap_target(ins.address,mapping,target,len(code))
      #print "(pre)new length: %s"%len(callback_code)
      #print "target: %s"%hex(target)
      #print "newtarget: %s"%newtarget
      if no_pic and target != get_pc_thunk:
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
    template_before = '''
    mov [esp-32], eax
    mov eax, %s
    %s
    '''
    exec_call = '''
    push %s
    '''
    so_call_before = '''
    push ebx
    call $+5
    '''
    so_call_after = '''
    pop ebx
    sub ebx,%s
    xchg ebx,[esp]
    '''
    template_after = '''
    call $+%s
    mov [esp-4], eax
    mov eax, [esp-%s]
    jmp [esp-4]
    '''
    template_nopic = '''
    call $+%s
    mov [esp-4], eax
    mov eax, [esp-%s]
    %s [esp-4]
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
    if no_pic:
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
          code += asm(so_call_after%( (mapping[ins.address]+len(code)+newbase) - (ins.address+len(ins.bytes)) ) )
          #print 'CODE LEN/1: %d\n%s'%(len(code),code.encode('hex'))
        else:
          code += asm(so_call_after%( (0x8f+newbase) - (ins.address+len(ins.bytes)) ) )
          #print 'CODE LEN/0: %d\n%s'%(len(code),code.encode('hex'))
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
      code += asm( template_nopic%(lookup_target,32,ins.mnemonic) )
    elif ins.mnemonic == 'call':
      code += asm(template_after%(lookup_target,28))
    else:  
      code += asm(template_after%(lookup_target,32))
    return code
  
  def get_remap_callbacks_code(self,insaddr,mapping,target):
    '''Checks whether the target destination (expressed as the opcode string from a jmp/call instruction)
       is in the got, then checks if it matches a function with callbacks.  It then rewrites the
       addresses if necessary.  This will *probably* always be from jmp instructions in the PLT.
       NOTE: This assumes it does not have any code inserted before it, and that it comprises the first
       special instructions inserted for an instruction.'''
    if self.memory_ref_string.match(target):
      address = int(memory_ref_string.match(target).group('address'), 16)
      if address in self.context.plt['entries']:
        if self.context.plt['entries'][address] in self.context.callbacks:
          print 'Found library call with callbacks: %s'%self.context.plt['entries'][address]
          return self.get_callback_code( insaddr, mapping, self.context.callbacks[self.context.plt['entries'][address]] )
    return b''
  
  def get_callback_code(self,address,mapping,cbargs):
    '''Remaps each callback argument on the stack based on index.  cbargs is an array of argument indices
       that let us know where on the stack we must rewrite.  We insert code for each we must rewrite.'''
    callback_template_before = '''
    mov eax, [esp+(%s*4)]
    '''
    callback_template_after = '''
    call $+%s
    mov [esp+(%s*4)], eax
    '''
    code = asm('push eax') #Save eax, use to hold callback address
    for ind in cbargs:
      #Add 2 because we must skip over the saved value of eax and the return value already pushed
      #ASSUMPTION: before this instruction OR this instruction if it IS a call, a return address was
      #pushed.  Since this *probably* is taking place inside the PLT, in all probability this is a
      #jmp instruction, and the call that got us *into* the PLT pushed a return address, so we can't rely
      #on the current instruction to tell us this either way.  Therefore, we are *assuming* that the PLT
      #is always entered via a call instruction, or that somebody is calling an address in the GOT directly.
      #If code ever jmps based on an address in the got, we will probably corrupt the stack.
      cb_before = callback_template_before%( ind + 2 )
      code += asm(cb_before) #Assemble this part first so we will know the offset to the lookup function
      size = len(code)
      lookup_target = self.remap_target( address, mapping, lookup_function_offset, size )
      cb_after = callback_template_after%( lookup_target, ind + 2 )
      code += asm(cb_after) #Save the new address over the original
    code += asm('pop eax') #Restore eax
    return code
  
  def in_plt(self,target):
    return target in range(self.context.plt['addr'],self.context.plt['addr']+self.context.plt['size'])
  
  def get_plt_entry(self,target):
    #It seems that an elf does not directly give a mapping from each entry in the plt.
    #Instead, it maps from the got entries instead, making it unclear exactly where objdump
    #gets the information.  For our purposes, since all the entries in the plt jump to the got
    #entry, we can read the destination address from the jmp instruction.
    #TODO: ensure works for x64
    offset = target - self.context.plt['addr'] #Get the offset into the plt
    dest = self.context.plt['data'][offset+2:offset+2+4] #Get the four bytes of the GOT address
    dest = struct.unpack('<I',dest)[0] #Convert to integer, respecting byte endianness
    if dest in self.context.plt['entries']:
      return self.context.plt['entries'][dest] #If there is an entry, return that; the name of the function
    return None #Some entries may be a jump to the start of the plt (no entry)
  
  def remap_target(self,addr,mapping,target,offs): #Only works for statically identifiable targets
    newtarget = '0x8f'
    if mapping is not None and target in mapping:#Second pass, known mapping
      newtarget = mapping[target]-(mapping[addr]+offs) #Offset from curr location in mapping
      newtarget = hex(newtarget)
      #print "original target: %s"%hex(target)
      #print "%s-(%s+%s) = %s"%(hex(mapping[target]),hex(mapping[addr]),hex(offs),newtarget)
    return newtarget
