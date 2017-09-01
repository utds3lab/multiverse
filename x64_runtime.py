from x64_assembler import _asm,asm

class X64Runtime(object):
  def __init__(self,context):
    self.context = context
    self.context.global_lookup = 0x200000 # Set global lookup offset for 64-bit

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
    #TODO: support lookup for binary/library combination
    lookup_template = '''
  	push rbx
  	mov rbx,rax
  	lea rax, [rip-%s]
    	%s
  	jb outside
  	cmp rbx,%s
  	jae outside
  	mov ebx,[rax+rbx*4+%s]
  	cmp ebx, 0xffffffff
  	je failure
  	add rax,rbx
  	pop rbx
  	ret
    outside:
  	%s
  	mov rax,rbx
  	pop rbx
  	mov QWORD PTR [rsp-64],%s
    	jmp [rsp-64]
    failure:
  	hlt
    '''
    exec_code = '''
    	sub rbx,%s
    '''
    exec_restore = '''
    	add rbx,%s
    '''
    #Notice that we only move a DWORD from the mapping (into ebx) because the
    #mapping only stores 4-byte offsets.  Therefore, if a text section is >4GB,
    #this mapping strategy will fail
    exec_only_lookup = '''
    lookup:
  	push rbx
  	mov rbx,rax
  	lea rax, [rip-%s]
  	sub rbx,%s
  	jb outside
  	cmp rbx,%s
  	jae outside
  	mov ebx, [rax+rbx*4+%s]
  	add rax,rbx
  	pop rbx
  	ret
  
    outside:
  	add rbx,%s
  	mov rax,[rsp+16]
  	call lookup
  	mov [rsp+16],rax
  	mov rax,rbx
  	pop rbx
  	ret
    '''
    #For an .so, it can be loaded at an arbitrary address, so we cannot depend on
    #the base address being in a fixed location.  Therefore, we instead compute 
    #the old text section's start address by using the new text section's offset
    #from it.  
    # rax holds the address of the lookup function, which is at the start of the new
    # section we are adding.
    # rbx at the start holds the address we want to look up, and we want to compute
    # how many bytes the address is from the start of the original text section.  So
    # we add the newbase address to rbx to add the offset there is between the old and
    # new text sections, and then subtract off the address of the lookup.
    so_code = '''
	add rbx, %s
	sub rbx, rax
    '''
    so_restore = '''
	add rbx, rax
	sub rbx, %s
    '''
    #retrieve rip 11 bytes after start of lookup function (right after first lea instruction)
    if self.context.write_so:
      return _asm(lookup_template%(lookup_off+11,so_code%(self.context.newbase),size,mapping_off,so_restore%(self.context.newbase),self.context.global_lookup))
    elif self.context.exec_only:
      return _asm( exec_only_lookup%(lookup_off+11,base,size,mapping_off,base) )
    else:
      return _asm(lookup_template%(lookup_off+11,exec_code%base,size,mapping_off,exec_restore%base,self.context.global_lookup))

  def get_secondary_lookup_code(self,base,size,sec_lookup_off,mapping_off):
    '''This secondary lookup is only used when rewriting only the main executable.  It is a second, simpler
       lookup function that is used by ret instructions and does NOT rewrite a return address on the stack
       when the destination is outside the mapping.  It instead simply returns the original address and that's
       it.  The only reason I'm doing this by way of a secondary lookup is this should be faster than a
       a parameter passed at runtime, so I need to statically have an offset to jump to in the case of returns.
       This is a cleaner way to do it than split the original lookup to have two entry points.'''
    #Notice that we only move a DWORD from the mapping (into ebx) because the
    #mapping only stores 4-byte offsets.  Therefore, if a text section is >4GB,
    #this mapping strategy will fail
    secondary_lookup = '''
    lookup:
  	push rbx
  	mov rbx,rax
        lea rax, [rip-%s]
  	sub rbx,%s
  	jb outside
  	cmp rbx,%s
  	jae outside
  	mov ebx,[rax+rbx*4+%s]
  	add rax,rbx
  	pop rbx
  	ret
  
    outside:
  	add rbx,%s
  	mov rax,rbx
  	pop rbx
  	ret
    '''
    return _asm( secondary_lookup%(sec_lookup_off+11,base,size,mapping_off,base) )

  def get_global_lookup_code(self):
    #TODO: Support global lookup, executable + library rewriting
    #I have to modify it so it will assemble since we write out the global lookup
    #regardless of whether it's used, but it obviously won't work in this state...
    #addr - global_mapping[index].start <= global_mapping[index].length
    # rbx = length
    # rcx = base/entry
    # rdx = index
    # r10 = entry
    #struct gm_entry {
    #	unsigned long lookup_function;
    #	unsigned long start;
    #	unsigned long length;
    #};
    #TODO: still need to handle code entering the loader region....
    '''
	; Get rid of sysinfo comparison because we instead are going to be comparing based on entire address ranges
	;cmp rax,[%s]		; If rax is sysinfo
    	;je sysinfo		; Go to rewrite return address
    glookup:
	push rbx		; Save working registers
	push rcx
	push rdx
	push r10
	mov rcx, %s		; Load address of first entry
	mov rbx, [rcx]		; Load first value in first entry (lookup_function, serving as length)
	xor rdx, rdx		; Clear rdx
    searchloop:
	cmp rbx, rdx		; Check if we are past last entry
	je failure		; Did not find successful entry, so fail
	add rcx, 24		; Set rcx to next entry
	mov r10, [rcx+8]	; Load second item in entry (start)
	neg r10			; Negate r10 so it can act like it is being subtracted
	add r10, rax		; Get difference between lookup address and start
	cmp r10, [rcx+16]	; Compare: address - start <= end - start (length)
	jle success		; If so, we found the right entry.
	inc rdx			; Add one to our index
	jmp searchloop		; Loop for next entry
    success:
	mov rcx,[rcx]		; Load lookup address into rcx so we can compare it to 0
	test rcx,rcx		; If lookup address is zero it means this region is not rewritten!
	jz external		; Jump to external so we can rewrite return address on the stack (assume only calls into external regions)
	call rcx		; Call the lookup, as specified by the first value in global mapping entry (lookup_function) 	
	pop r10			; rax should now have the right value; restore the saved values and ret
	pop rdx
	pop rcx
	pop rbx
	ret
    external:
    	push rax		; Save original rax
    	mov rax,[rsp+48]	; Load the return address we want to overwrite (the 4 registers we pushed in glookup + address of instruction calling the local lookup + rax)
    	call glookup		; Lookup the translated value
    	mov [rsp+48],rax	; Overwrite with the translated value
    	pop rax			; Restore original rax, returned unmodified so we call unmodified external code
	pop r10			; Restore all saved registers and return
	pop rdx
	pop rcx
	pop rbx
  	ret
    failure:
	hlt
    '''
    global_lookup_template = '''
    glookup:		
	push rbx		
	push rcx
	push rdx
	push r10
	mov rcx, %s		
	mov rbx, [rcx]		
	xor rdx, rdx		
    searchloop:
	cmp rbx, rdx		
	je failure		
	add rcx, 24		
	mov r10, [rcx+8]
	neg r10	
	add r10, rax	
	cmp r10, [rcx+16]
	jle success
	inc rdx			
	jmp searchloop		
    success:
	mov rcx,[rcx]
	test rcx,rcx
	jz external
	call rcx		 
	pop r10			
	pop rdx
	pop rcx
	pop rbx
	ret
    external:
    	push rax		
    	mov rax,[rsp+48]	
    	call glookup		
    	mov [rsp+48],rax	
    	pop rax	
	pop r10			
	pop rdx
	pop rcx
	pop rbx		
  	ret
    failure:
	hlt
    '''
    return _asm(global_lookup_template%(self.context.global_sysinfo+8))

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
  	mov [rsp-8],rsi
  	mov [rsp-16],rcx
  	mov rsi,[rsp]
  	mov rcx,rsp
  	lea rcx,[rcx+rsi*8+8]
    loopenv:
  	add rcx,8
  	mov rsi,[rcx]
  	test rsi,rsi
  	jnz loopenv
  	add rcx,8
    loopaux:
  	mov rsi,[rcx]
  	cmp rsi,32
  	jz foundsysinfo
  	test rsi,rsi
  	jz restore
  	add rcx,16
  	jmp loopaux
    foundsysinfo:
  	mov rsi,[rcx+8]
  	mov [%s],rsi
    restore:
  	mov rsi,[rsp-8]
  	mov rcx,[rsp-16]
    	push %s
    	call [rsp]
    	add rsp,8
    	mov DWORD PTR [rsp-16], %s
  	jmp [rsp-16]
    '''
    return _asm(auxvec_template%(self.context.global_sysinfo,self.context.global_lookup+self.context.popgm_offset,self.context.newbase+entry))

  def get_popgm_code(self):
    #pushad and popad do NOT exist in x64,
    #so we must choose which registers must be preserved at program start
    #TODO: For now we skip actually calling popgm, because it will have to be
    #completely re-engineered, so we will need to change the offset to 0x11 
    #once we have fixed popgm for x64
    call_popgm = '''
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    mov rdi, %s
    call $+0x0d
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    ret
    '''
    popgmbytes = asm(call_popgm%(self.context.global_sysinfo+8))
    with open('x64_%s' % self.context.popgm) as f:
      popgmbytes+=f.read()
    return popgmbytes

  def get_global_mapping_bytes(self):
    #TODO: support global mapping
    globalbytes = self.get_global_lookup_code()
    #globalbytes+='\0' #flag field
    globalbytes += self.get_popgm_code()
    globalbytes += '\0\0\0\0\0\0\0\0' #sysinfo field
    # Global mapping (0x6000 0x00 bytes).  This contains space for 1024 entries:
    # 8 * 3 = 24 bytes per entry * 1024 entries = 0x6000 (24576) bytes.  If a binary
    # has more than 1024 libraries, the program will most likely segfault.
    globalbytes += '\x00'*0x6000
    return globalbytes
