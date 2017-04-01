from x64_assembler import _asm,asm

class X64Runtime(object):
  def __init__(self,context):
    self.context = context

  def get_lookup_code(self,base,size,lookup_off,mapping_off):
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
  	jmp global_lookup	;Check if global lookup can find this
    failure:
  	hlt
    '''
    lookup_template = '''
  	push ebx
  	mov ebx,eax
  	call get_eip
    get_eip:
  	pop eax
  	sub eax,%s
    	%s
  	jb outside
  	cmp ebx,%s
  	jae outside
  	mov ebx,[eax+ebx*4+%s]
  	cmp ebx, 0xffffffff
  	je failure
  	add eax,ebx
  	pop ebx
  	ret
    outside:
  	%s
  	mov eax,ebx
  	pop ebx
  	mov DWORD PTR [esp-32],%s
    	jmp [esp-32]
    failure:
  	hlt
    '''
    exec_code = '''
    	sub ebx,%s
    '''
    exec_restore = '''
    	add ebx,%s
    '''
    exec_only_lookup = '''
    lookup:
  	push ebx
  	mov ebx,eax
  	call get_eip
    get_eip:
  	pop eax
  	sub eax,%s
  	sub ebx,%s
  	jb outside
  	cmp ebx,%s
  	jae outside
  	mov ebx,[eax+ebx*4+%s]
  	add eax,ebx
  	pop ebx
  	ret
  
    outside:
  	add ebx,%s
  	mov eax,[esp+8]
  	call lookup
  	mov [esp+8],eax
  	mov eax,ebx
  	pop ebx
  	ret
    '''
    #For an .so, it can be loaded at an arbitrary address, so we cannot depend on
    #the base address being in a fixed location.  Therefore, we instead compute 
    #the old text section's start address by using the new text section's offset
    #from it.  The new text section's offset equals the lookup address and is
    #stored in eax.  I use lea instead of add because it doesn't affect the flags,
    #which are used to determine if ebx is outside the range.
    so_code = '''
    	sub eax,%s
    	sub ebx,eax
    	lea eax,[eax+%s]
    '''
    so_restore = '''
    	sub eax,%s
    	add ebx,eax
    	add eax,%s
    '''
    #retrieve eip 8 bytes after start of lookup function
    if self.context.write_so:
      return _asm(lookup_template%(lookup_off+8,so_code%(self.context.newbase,self.context.newbase),size,mapping_off,so_restore%(self.context.newbase,self.context.newbase),self.context.global_lookup))
    elif self.context.exec_only:
      return _asm( exec_only_lookup%(lookup_off+8,base,size,mapping_off,base) )
    else:
      return _asm(lookup_template%(lookup_off+8,exec_code%base,size,mapping_off,exec_restore%base,self.context.global_lookup))

  def get_secondary_lookup_code(self,base,size,sec_lookup_off,mapping_off):
    '''This secondary lookup is only used when rewriting only the main executable.  It is a second, simpler
       lookup function that is used by ret instructions and does NOT rewrite a return address on the stack
       when the destination is outside the mapping.  It instead simply returns the original address and that's
       it.  The only reason I'm doing this by way of a secondary lookup is this should be faster than a
       a parameter passed at runtime, so I need to statically have an offset to jump to in the case of returns.
       This is a cleaner way to do it than split the original lookup to have two entry points.'''
    secondary_lookup = '''
    lookup:
  	push ebx
  	mov ebx,eax
  	call get_eip
    get_eip:
  	pop eax
  	sub eax,%s
  	sub ebx,%s
  	jb outside
  	cmp ebx,%s
  	jae outside
  	mov ebx,[eax+ebx*4+%s]
  	add eax,ebx
  	pop ebx
  	ret
  
    outside:
  	add ebx,%s
  	mov eax,ebx
  	pop ebx
  	ret
    '''
    return _asm( secondary_lookup%(sec_lookup_off+8,base,size,mapping_off,base) )

  def get_global_lookup_code(self):
    global_lookup_template = '''
    	cmp eax,[%s]
    	jz sysinfo
    glookup:
    	cmp BYTE PTR [gs:%s],1
    	jz failure
    	mov BYTE PTR [gs:%s],1
    	push eax
    	shr eax,12
    	shl eax,2
    	mov eax,[%s+eax]
    	mov DWORD PTR [esp-32],eax
    	cmp eax, 0xffffffff
    	jz abort
    	test eax,eax
    	jz loader
    	pop eax
          call [esp-36]
    	mov BYTE PTR [gs:%s],0
    	ret
    loader:
    	mov BYTE PTR [gs:%s],0
    	pop eax
    sysinfo:
    	push eax
    	mov eax,[esp+8]
    	call glookup
    	mov [esp+8],eax
    	pop eax
  	ret
    failure:
    	hlt
    abort:
    	hlt
    	mov eax,1
    	int 0x80
    '''
    return _asm(global_lookup_template%(self.context.global_sysinfo,self.context.global_flag,self.context.global_flag,self.context.global_sysinfo+4,self.context.global_flag,self.context.global_flag))

  def get_auxvec_code(self,entry):
    #Example assembly for searching the auxiliary vector
    '''
  	mov [esp-4],esi		;I think there's no need to save these, but in case somehow the
  	mov [esp-8],ecx		;linker leaves something of interest for _start, let's save them
  	mov esi,[esp]		;Retrieve argc
  	mov ecx,esp		;Retrieve address of argc
  	lea ecx,[ecx+esi*4+4]	;Skip argv
    loopenv:			;Iterate through each environment variable
  	add ecx,4		;The first loop skips over the NULL after argv
  	mov esi,[ecx]		;Retrieve environment variable
  	test esi,esi		;Check whether it is NULL
  	jnz loopenv		;If not, continue through environment vars
  	add ecx,4		;Hop over 0 byte to first entry
    loopaux:			;Iterate through auxiliary vector, looking for AT_SYSINFO (32)
  	mov esi,[ecx]		;Retrieve the type field of this entry
  	cmp esi,32		;Compare to 32, the entry we want
  	jz foundsysinfo		;Found it
  	test esi,esi		;Check whether we found the entry signifying the end of auxv
  	jz restore		;Go to _start if we reach the end
  	add ecx,8		;Each entry is 8 bytes; go to next
  	jmp loopaux
    foundsysinfo:
  	mov esi,[ecx+4]		;Retrieve sysinfo address
  	mov [sysinfo],esi	;Save address
    restore:
  	mov esi,[esp-4]
  	mov ecx,[esp-8]
    	push global_mapping	;Push address of global mapping for popgm
    	call popgm
    	add esp,4		;Pop address of global mapping
  	jmp realstart
    '''
    auxvec_template = '''
  	mov [esp-4],esi
  	mov [esp-8],ecx
  	mov esi,[esp]
  	mov ecx,esp
  	lea ecx,[ecx+esi*4+4]
    loopenv:
  	add ecx,4
  	mov esi,[ecx]
  	test esi,esi
  	jnz loopenv
  	add ecx,4
    loopaux:
  	mov esi,[ecx]
  	cmp esi,32
  	jz foundsysinfo
  	test esi,esi
  	jz restore
  	add ecx,8
  	jmp loopaux
    foundsysinfo:
  	mov esi,[ecx+4]
  	mov [%s],esi
    restore:
  	mov esi,[esp-4]
  	mov ecx,[esp-8]
    	push %s
    	call [esp]
    	add esp,4
    	mov DWORD PTR [esp-12], %s
  	jmp [esp-12]
    '''
    return _asm(auxvec_template%(self.context.global_sysinfo,self.context.global_lookup+self.context.popgm_offset,self.context.newbase+entry))

  def get_popgm_code(self):
    #TODO: pushad and popad do NOT exist in x64, so we must choose which registers must be preserved at program start
    call_popgm = '''
    pushad
    push %s
    call $+0xa
    add esp,4
    popad
    ret
    '''
    popgmbytes = asm(call_popgm%(self.context.global_sysinfo+4))
    with open(self.context.popgm) as f:
      popgmbytes+=f.read()
    return popgmbytes

  def get_global_mapping_bytes(self):
    globalbytes = self.get_global_lookup_code()
    #globalbytes+='\0' #flag field
    globalbytes += self.get_popgm_code()
    globalbytes += '\0\0\0\0' #sysinfo field
    #Global mapping (0x3ffff8 0xff bytes) ending at kernel addresses.  Note it is NOT ending
    #at 0xc0000000 because this boundary is only true for 32-bit kernels.  For 64-bit kernels,
    #the application is able to use most of the entire 4GB address space, and the kernel only
    #holds onto a tiny 8KB at the top of the address space.
    globalbytes += '\xff'*((0xffffe000>>12)<<2) 
    return globalbytes
